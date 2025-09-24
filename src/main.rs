use tracing::error;
mod crypto;
mod model;
mod storage;
mod pdf;
mod alert;

use axum::{routing::{post, get}, Router, Json, extract::{Path, State}, response::IntoResponse};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use std::{net::SocketAddr, path::PathBuf};
use crate::crypto::{VaultCrypto, advance_vaultseal_head};
use crate::model::{ScanEvent, SealedEvent, AnomalyFlag, Severity, EventType};
use crate::storage::{Store, ShipmentMeta};

#[derive(Clone)]
struct AppState {
    store: Store,
    vault: VaultCrypto,
    data_root: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let data_root = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".into());
    let store = Store::open(&data_root)?;
    let vault = VaultCrypto::from_env()?;
    let state = AppState { store, vault, data_root: PathBuf::from(&data_root) };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/scan", post(post_scan))
        .route("/shipments", get(list_shipments))
        .route("/shipments/:id/events", get(list_events))
        .route("/shipments/:id/export.pdf", get(export_pdf))
        .route("/shipments/:id/export_forensic.json", get(export_forensic))
        .route("/shipments/:id/geofence", post(set_geofence))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8088".parse().unwrap();
    println!("➡ SupplyChain VaultSeal listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn health() -> &'static str { "ok" }

async fn list_shipments(State(app): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let v = app.store.list_shipments().map_err(internal)?;
    Ok(Json(json!({ "shipments": v })))
}

async fn list_events(Path(id): Path<String>, State(app): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let v = app.store.list_events(&id).map_err(internal)?;
    Ok(Json(json!({ "shipment_id": id, "events": v })))
}

async fn post_scan(State(app): State<AppState>, Json(mut ev): Json<ScanEvent>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ev = ev.with_server_ts();

    let cia_hex = app.vault.cia_hash_hex(&ev, &ev.device_id, &ev.handler_id).map_err(internal)?;

    let mut meta = app.store.shipment_meta(&ev.shipment_id).map_err(internal)?;
    let anomalies = compute_anomalies(&ev, &meta);

    let new_head = advance_vaultseal_head(&meta.head_hex, &cia_hex);

    let vault_dir = app.store.vault_dir_for(&ev.shipment_id);
    let fname = format!("{}-{}.vault", OffsetDateTime::now_utc().unix_timestamp(), short(&cia_hex));
    let vault_path = vault_dir.join(&fname);
    app.vault.encrypt_vault(&ev, &vault_path).map_err(internal)?;

    let is_flame = matches!(ev.event_type, EventType::Destroy);

    let sealed = SealedEvent {
        event: ev,
        server_ts: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
        cia_hash_hex: cia_hex.clone(),
        vaultseal_head_hex: new_head.clone(),
        vault_path: vault_path.to_string_lossy().to_string(),
        anomalies,
        memory_flame: is_flame,
    };
    app.store.append_event(&sealed).map_err(internal)?;

    meta.head_hex = new_head;
    meta.last_event_type = Some(format!("{:?}", sealed.event.event_type));
    meta.last_server_ts = Some(sealed.server_ts.clone());
    app.store.set_shipment_meta(&sealed.event.shipment_id, &meta).map_err(internal)?;

    let sealed_for_alert = sealed.clone();
    tokio::spawn(async move { alert::maybe_alert(&sealed_for_alert).await; });

    Ok(Json(json!({ "ok": true, "sealed": sealed })))
}

#[derive(Deserialize)]
struct GeofenceReq { lat: f64, lon: f64, radius_km: f64 }

async fn set_geofence(
    Path(id): Path<String>,
    State(app): State<AppState>,
    Json(req): Json<GeofenceReq>
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut meta = app.store.shipment_meta(&id).map_err(internal)?;
    meta.geofence_lat = Some(req.lat);
    meta.geofence_lon = Some(req.lon);
    meta.geofence_radius_km = Some(req.radius_km);
    app.store.set_shipment_meta(&id, &meta).map_err(internal)?;
    Ok(Json(json!({ "ok": true, "shipment_id": id, "geofence": { "lat": req.lat, "lon": req.lon, "radius_km": req.radius_km } })))
}

async fn export_pdf(Path(id): Path<String>, State(app): State<AppState>) -> impl IntoResponse {
    use axum::http::{header, StatusCode};

    match app.store.list_events(&id) {
        Ok(events) => match crate::pdf::build_pdf(&id, &events) {
            Ok(bytes) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/pdf"),
                    (header::CONTENT_DISPOSITION, &format!("inline; filename=\"{}.pdf\"", id)),
                ],
                bytes,
            ).into_response(),
            Err(e) => {
                error!("export_pdf build_pdf error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "PDF export failed").into_response()
            }
        },
        Err(e) => {
            error!("export_pdf list_events error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "PDF export failed").into_response()
        }
    }
}


async fn export_forensic(Path(id): Path<String>, State(app): State<AppState>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let events = app.store.list_events(&id).map_err(internal)?;
    Ok(Json(json!({ "shipment_id": id, "events": events })))
}

fn compute_anomalies(ev: &crate::model::ScanEvent, meta: &ShipmentMeta) -> Vec<AnomalyFlag> {
    let mut out = vec![];

    if let Some(prev) = &meta.last_event_type {
        let curr = format!("{:?}", ev.event_type);
        if is_illegal_transition(prev, &curr) {
            out.push(AnomalyFlag{
                code: "illegal_transition".into(),
                message: format!("Illegal transition {} → {}", prev, curr),
                severity: Severity::Warn,
            });
        }
        if let Some(prev_ts) = &meta.last_server_ts {
            if &ev.ts.clone().unwrap_or_else(|| "".into()) < prev_ts {
                out.push(AnomalyFlag{
                    code: "time_regression".into(),
                    message: format!("Client ts {:?} earlier than last server ts {}", ev.ts, prev_ts),
                    severity: Severity::Info,
                });
            }
        }
    }

    if let (Some(lat), Some(lon), Some(r_km)) = (meta.geofence_lat, meta.geofence_lon, meta.geofence_radius_km) {
        if let Some(g) = &ev.gps {
            let d = haversine_km(lat, lon, g.lat, g.lon);
            if d > r_km {
                out.push(AnomalyFlag{
                    code: "geofence_violation".into(),
                    message: format!("GPS outside geofence by {:.2} km", d - r_km),
                    severity: Severity::Warn,
                });
            }
        }
    }

    if matches!(ev.event_type, EventType::Ship | EventType::Receive | EventType::Handoff) && ev.notes.as_deref() == Some("DUPLICATE") {
        out.push(AnomalyFlag{
            code: "duplicate_scan".into(),
            message: "Marked duplicate by operator".into(),
            severity: Severity::Info,
        });
    }

    if ev.override_reason.is_some() && ev.override_reason.as_deref().unwrap().trim().is_empty() {
        out.push(AnomalyFlag{
            code: "override_no_reason".into(),
            message: "Override used but no reason provided".to_string(),
            severity: Severity::Warn,
        });
    }

    out
}

fn is_illegal_transition(prev: &str, curr: &str) -> bool {
    match (prev, curr) {
        ("Create", "Create") => true,
        ("Ship", "Ship") => true,
        ("Ship", "Pack") => true,
        ("Receive", "Create") => true,
        ("Destroy", _) => true,
        _ => false,
    }
}

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0_f64;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat/2.0).sin().powi(2)
          + lat1.to_radians().cos()*lat2.to_radians().cos()
          * (dlon/2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    r * c
}

fn short(h: &str) -> String { h.chars().take(12).collect() }
fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) { (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)) }
