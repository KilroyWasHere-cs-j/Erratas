use image::{GrayImage, ImageReader};
use imageproc::contrast::{ThresholdType, otsu_level, threshold_mut};
use rustrict::{CensorStr, Type};
use std::error::Error;
use std::io::Cursor;
use tesseract::Tesseract;

use crate::types::{ErratasJob, RealFileType};

// TODO: Scan PII patterns for regex matches.

// TODO: Scan profanity patterns for word-list matches.

fn has_bad_text(text: &str) -> bool {
    text.is(Type::PROFANE | Type::OFFENSIVE)
}

pub fn pii() {}

fn preprocess(bytes: &[u8]) -> Result<GrayImage, Box<dyn Error>> {
    let image = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()?
        .decode()?;
    let mut gray_image = image.to_luma8();
    let threshold = otsu_level(&gray_image);
    threshold_mut(&mut gray_image, threshold, ThresholdType::Binary);
    Ok(gray_image)
}

pub fn scan_content(erratas_job: &mut ErratasJob) -> Result<&mut ErratasJob, Box<dyn Error>> {
    if erratas_job.file_info.file_type == RealFileType::Image {
        let gray_image = preprocess(&erratas_job.file_info.contents)?;
        let mut ocr = Tesseract::new(None, Some("eng"))?;
        let frame = gray_image.as_raw();
        let width = gray_image.width() as i32;
        let height = gray_image.height() as i32;
        ocr = ocr.set_frame(frame, width, height, 1, width)?;

        let text = ocr.get_text()?;

        println!("{}", has_bad_text(&text));
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
                content_flag: crate::types::ErratasContentFlag::Scanning,
                file_type: RealFileType::Image,
                file_sub_type: crate::types::RealFileSubType::Unknown(
                    crate::types::UnknownSubType::Unknown,
                ),
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
