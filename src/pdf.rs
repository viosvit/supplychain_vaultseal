// src/pdf.rs
use anyhow::{anyhow, Context, Result};
use printpdf::{BuiltinFont, Mm, PdfDocument};
use std::io::BufWriter;

use crate::model::SealedEvent;

/// Build a valid A4 PDF using built-in fonts (no runtime font files).
pub fn build_pdf(ship_id: &str, events: &[SealedEvent]) -> Result<Vec<u8>> {
    let (doc, page1, layer1) = PdfDocument::new(
        &format!("VaultSeal {}", ship_id),
        Mm(210.0), // A4 width
        Mm(297.0), // A4 height
        "Layer 1",
    );

    let header_font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let row_font = doc.add_builtin_font(BuiltinFont::Courier)?; // monospace for tidy columns

    let page_w = Mm(210.0);
    let page_h = Mm(297.0);
    let mut current = doc.get_page(page1).get_layer(layer1);

    let mut y = Mm(280.0);
    let left = Mm(12.0);

    // Header
    current.use_text(
        format!("Shipment {} — VaultSeal Report", ship_id),
        14.0,
        left,
        y,
        &header_font,
    );
    y -= Mm(10.0);

    current.use_text(format!("Total events: {}", events.len()), 10.0, left, y, &header_font);
    y -= Mm(8.0);

    // Rows (with very simple pagination)
    for e in events {
        if y.0 < 15.0 {
            let (p, l) = doc.add_page(page_w, page_h, "Layer");
            current = doc.get_page(p).get_layer(l);
            y = Mm(280.0);

            current.use_text(
                format!("Shipment {} — VaultSeal Report (cont.)", ship_id),
                12.0,
                left,
                y,
                &header_font,
            );
            y -= Mm(8.0);
        }

        let ev = &e.event;
        let line = format!(
            "[{}] {:?} pkg={} handler={} facility={} gps={:?} cia={} head={}",
            e.server_ts,
            ev.event_type,
            ev.package_id.as_deref().unwrap_or("-"),
            ev.handler_id,
            ev.facility_id,
            ev.gps.as_ref().map(|g| (g.lat, g.lon)),
            &e.cia_hash_hex[..12],
            &e.vaultseal_head_hex[..12]
        );

        current.use_text(line, 9.0, left, y, &row_font);
        y -= Mm(5.0);
    }

    // Save to bytes
    let mut writer = BufWriter::new(Vec::<u8>::new());
    doc.save(&mut writer).context("pdf save")?;
    let buf = writer.into_inner().map_err(|e| anyhow!("BufWriter into_inner: {}", e))?;
    Ok(buf)
}

/// Optional helper to write straight to a file.
pub fn build_pdf_to_file(ship_id: &str, events: &[SealedEvent], path: &str) -> Result<()> {
    let bytes = build_pdf(ship_id, events)?;
    std::fs::write(path, &bytes)?;
    Ok(())
}
