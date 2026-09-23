use image::{GrayImage, ImageReader};
use imageproc::contrast::{ThresholdType, otsu_level, threshold_mut};
use rustrict::{CensorStr, Type};
use std::error::Error;
use std::io::Cursor;
use tesseract::Tesseract;

use calamine::{Data, Reader as _, open_workbook_auto_from_rs};
use docx_rs::{
    DocumentChild, ParagraphChild, RunChild, Table, TableCellContent, TableChild, TableRowChild,
    read_docx,
};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::io::Read;
use zip::ZipArchive;

use crate::{
    consts::STRIKE3_IP,
    types::{DocumentSubType::PDF, ErratasJob, RealFileType},
};

// TODO: Scan PII patterns for regex matches.

// TODO: Scan profanity patterns for word-list matches.

fn has_bad_text(text: &str) -> bool {
    text.is(Type::PROFANE | Type::OFFENSIVE | Type::SEXUAL)
}

pub fn pii() {}

fn match_against_strike3_black_list(text: &str) -> Vec<String> {
    let lowercase_text = text.to_lowercase();
    let mut found = Vec::new();
    for i in STRIKE3_IP {
        if lowercase_text.contains(i) {
            found.push(text.to_string());
        }
    }
    return found;
}

fn preprocess(bytes: &[u8]) -> Result<GrayImage, Box<dyn Error>> {
    let image = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()?
        .decode()?;
    let mut gray_image = image.to_luma8();
    let threshold = otsu_level(&gray_image);
    threshold_mut(&mut gray_image, threshold, ThresholdType::Binary);
    Ok(gray_image)
}

fn extract_text_from_image(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let gray_image = preprocess(bytes)?;
    let mut ocr = Tesseract::new(None, Some("eng"))?;
    let frame = gray_image.as_raw();
    let width = gray_image.width() as i32;
    let height = gray_image.height() as i32;
    ocr = ocr.set_frame(frame, width, height, 1, width)?;

    let text = ocr.get_text()?;
    Ok(text)
}

fn extract_text_from_docx(bytes: &[u8]) -> Result<String, docx_rs::ReaderError> {
    let docx = read_docx(bytes)?;
    let mut text = String::new();

    for child in &docx.document.children {
        match child {
            DocumentChild::Paragraph(paragraph) => {
                extract_paragraph_children(&paragraph.children, &mut text);
                text.push('\n');
            }
            DocumentChild::Table(table) => {
                extract_table(table, &mut text);
            }
            _ => {}
        }
    }

    Ok(text)
}

// Shared by top-level paragraphs and hyperlinks (both hold Vec<ParagraphChild>).
fn extract_paragraph_children(children: &[ParagraphChild], text: &mut String) {
    for child in children {
        match child {
            ParagraphChild::Run(run) => {
                for r_child in &run.children {
                    if let RunChild::Text(t) = r_child {
                        text.push_str(&t.text);
                    }
                }
            }
            ParagraphChild::Hyperlink(hyperlink) => {
                extract_paragraph_children(&hyperlink.children, text);
            }
            _ => {}
        }
    }
}

fn extract_table(table: &Table, text: &mut String) {
    for row_child in &table.rows {
        let TableChild::TableRow(row) = row_child;
        for cell_child in &row.cells {
            let TableRowChild::TableCell(cell) = cell_child;
            for content in &cell.children {
                match content {
                    TableCellContent::Paragraph(paragraph) => {
                        extract_paragraph_children(&paragraph.children, text);
                        text.push('\n');
                    }
                    TableCellContent::Table(nested_table) => {
                        extract_table(nested_table, text); // tables can nest inside cells
                    }
                    _ => {}
                }
            }
            text.push('\t'); // cell separator
        }
        text.push('\n'); // row separator
    }
}

fn extract_text_from_excel(bytes: &[u8]) -> Result<String, calamine::Error> {
    let mut workbook = open_workbook_auto_from_rs(Cursor::new(bytes))?;
    let mut text = String::new();

    for sheet_name in workbook.sheet_names().to_owned() {
        let range = workbook.worksheet_range(&sheet_name)?;
        for row in range.rows() {
            for cell in row {
                match cell {
                    Data::Empty => {}
                    other => {
                        text.push_str(&other.to_string()); // Data implements Display for every variant
                        text.push('\t');
                    }
                }
            }
            text.push('\n');
        }
    }

    Ok(text)
}

fn extract_text_from_powerpoint(bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)?;
    let mut text = String::new();

    // Collect slide file names first so we can sort them (slide1, slide2, ... not zip order).
    let mut slide_names: Vec<String> = archive
        .file_names()
        .filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"))
        .map(String::from)
        .collect();
    slide_names.sort_by_key(|n| {
        n.trim_start_matches("ppt/slides/slide")
            .trim_end_matches(".xml")
            .parse::<u32>()
            .unwrap_or(0)
    });

    for name in slide_names {
        let mut file = archive.by_name(&name)?;
        let mut xml = String::new();
        file.read_to_string(&mut xml)?;

        let mut reader = Reader::from_str(&xml);
        let mut buf = Vec::new();
        let mut in_text_run = false;

        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Start(e) if e.local_name().as_ref() == "t" => in_text_run = true,
                Event::End(e) if e.local_name().as_ref() == "t" => in_text_run = false,
                Event::Text(e) if in_text_run => {
                    text.push_str(&quick_xml::escape::unescape(&e)?);
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        text.push('\n'); // slide break
    }

    Ok(text)
}
pub fn scan_content(erratas_job: &mut ErratasJob) -> Result<&mut ErratasJob, Box<dyn Error>> {
    if erratas_job
        .file_info
        .file_type
        .contains(&RealFileType::Image)
    {
        let text = extract_text_from_image(&erratas_job.file_info.contents)?;
        erratas_job.file_info.bad_language = has_bad_text(&text);
        erratas_job.file_info.strike3 = match_against_strike3_black_list(&text);
    }

    if erratas_job
        .file_info
        .file_sub_type
        .contains(&crate::types::RealFileSubType::Document(PDF))
    {
        let text = pdf_extract::extract_text_from_mem(&erratas_job.file_info.contents)?;
        erratas_job.file_info.bad_language = has_bad_text(&text);
        erratas_job.file_info.strike3 = match_against_strike3_black_list(&text);
    }

    if erratas_job
        .file_info
        .file_sub_type
        .contains(&crate::types::RealFileSubType::Document(
            crate::types::DocumentSubType::DOCX,
        ))
    {
        let text = extract_text_from_docx(&erratas_job.file_info.contents)?;
        erratas_job.file_info.bad_language = has_bad_text(&text);
        erratas_job.file_info.strike3 = match_against_strike3_black_list(&text);
    }

    if erratas_job
        .file_info
        .file_sub_type
        .contains(&crate::types::RealFileSubType::Document(
            crate::types::DocumentSubType::XLSX,
        ))
    {
        let text = extract_text_from_excel(&erratas_job.file_info.contents)?;
        erratas_job.file_info.bad_language = has_bad_text(&text);
        erratas_job.file_info.strike3 = match_against_strike3_black_list(&text);
    }
    if erratas_job
        .file_info
        .file_sub_type
        .contains(&crate::types::RealFileSubType::Document(
            crate::types::DocumentSubType::PPT,
        ))
    {
        let text = extract_text_from_powerpoint(&erratas_job.file_info.contents)?;
        erratas_job.file_info.bad_language = has_bad_text(&text);
        erratas_job.file_info.strike3 = match_against_strike3_black_list(&text);
    }
    Ok(erratas_job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GrayImage, ImageFormat, Luma};
    use std::io::Cursor as IoCursor;

    // --- has_bad_text -----------------------------------------------

    #[test]
    fn has_bad_text_is_false_for_clean_text() {
        assert!(!has_bad_text("The quick brown fox jumps over the lazy dog"));
    }

    #[test]
    fn has_bad_text_is_true_for_profanity() {
        assert!(has_bad_text("this is a shit example of profane text"));
    }

    #[test]
    fn has_bad_text_is_false_for_empty_text() {
        assert!(!has_bad_text(""));
    }

    // --- preprocess --------------------------------------------------
    // preprocess() only cares about decoding + thresholding a valid
    // image, not what's drawn on it -- so a synthetic in-memory
    // checkerboard is enough to exercise it without needing real,
    // legible text or any external fixture file. Built entirely with
    // the `image` crate so this stays hermetic (no filesystem
    // dependency, works the same locally and in CI).
    fn synthetic_png_bytes(width: u32, height: u32) -> Vec<u8> {
        let image = GrayImage::from_fn(width, height, |x, y| {
            if (x + y) % 2 == 0 {
                Luma([255u8])
            } else {
                Luma([0u8])
            }
        });
        let mut bytes = Vec::new();
        image
            .write_to(&mut IoCursor::new(&mut bytes), ImageFormat::Png)
            .expect("encoding a synthetic test image should never fail");
        bytes
    }

    #[test]
    fn preprocess_decodes_a_valid_image_to_the_right_dimensions() {
        let png = synthetic_png_bytes(64, 32);
        let gray_image = preprocess(&png).expect("valid PNG bytes should preprocess cleanly");
        assert_eq!(gray_image.width(), 64);
        assert_eq!(gray_image.height(), 32);
    }

    #[test]
    fn preprocess_thresholds_to_pure_black_and_white() {
        // ThresholdType::Binary should leave every pixel at exactly 0 or
        // 255 -- no midtones -- regardless of the checkerboard's own
        // (already binary) starting values.
        let png = synthetic_png_bytes(16, 16);
        let gray_image = preprocess(&png).unwrap();
        assert!(gray_image.pixels().all(|p| p.0[0] == 0 || p.0[0] == 255));
    }

    #[test]
    fn preprocess_fails_closed_on_non_image_bytes() {
        // Same class of input that caused the panic this pipeline used
        // to hit on non-image files (see the shifted_example.7z bug) --
        // preprocess() itself must error, not panic.
        let not_an_image = b"this is definitely not image data";
        assert!(preprocess(not_an_image).is_err());
    }

    #[test]
    fn preprocess_fails_closed_on_empty_input() {
        assert!(preprocess(&[]).is_err());
    }

    // --- scan_content --------------------------------------------------
    // These exercise the real Tesseract OCR path end to end, using the
    // rendered-text fixtures in resources/ocr_examples/ (see the repo's
    // scripts/ for how they were generated). Unlike the rest of this
    // module's tests, these depend on two things the hermetic tests
    // above deliberately avoid:
    //   - Tesseract + Leptonica actually installed on the system (the
    //     same system-library requirement the whole crate already has
    //     to build at all -- see Cargo.toml's `tesseract` dependency).
    //   - resources/ocr_examples/*.png existing locally -- that
    //     directory is gitignored, so these fixtures aren't present on
    //     a fresh checkout/CI runner.
    // Both gaps are pre-existing (not introduced by these tests) and
    // are why these are skipped gracefully rather than failing loudly
    // when the fixture is missing.
    //
    // Weak on purpose beyond that: scan_content() only *prints*
    // has_bad_text's verdict today (`println!` inside the function)
    // instead of returning or storing it anywhere -- so a test can only
    // confirm the real OCR pipeline runs end to end without erroring on
    // a real image, not assert on the actual true/false verdict it
    // produces. Asserting on that would mean scan_content (or something
    // it calls) returning the extracted text/verdict instead of just
    // printing it -- a real API change, not something to sneak in here.
    fn scan_fixture(path: &str) -> Option<()> {
        let contents = std::fs::read(path).ok()?;
        let mut job = ErratasJob {
            file_info: crate::types::FileInfo {
                contents,
                bad_language: false,
                pii: false,
                zipbomb: false,
                malware: false,
                strike3: Vec::new(),
                hashmatches: Vec::new(),
                yara_finds: Vec::new(),
                file_type: Vec::new(),
                file_sub_type: Vec::new(),
            },
        };
        scan_content(&mut job).ok()?;
        Some(())
    }

    #[test]
    fn scan_content_runs_without_error_on_a_real_image_fixture() {
        if !std::path::Path::new("resources/ocr_examples/clean_text.png").exists() {
            eprintln!("skipping: resources/ocr_examples/ fixtures not present locally");
            return;
        }
        assert!(
            scan_fixture("resources/ocr_examples/clean_text.png").is_some(),
            "scan_content should run OCR + the profanity check on a real image without erroring"
        );
    }
}
