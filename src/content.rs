use image::{GrayImage, ImageReader};
use imageproc::contrast::{ThresholdType, otsu_level, threshold_mut};
use rustrict::CensorIter;
use rustrict::{CensorStr, Type};
use std::error::Error;
use std::io::Cursor;
use tesseract::Tesseract;

use crate::types::ErratasJob;

// TODO: Scan PII patterns for regex matches.

// TODO: Scan profanity patterns for word-list matches.

fn has_bad_text(text: &str) -> bool {
    text.is(Type::PROFANE | Type::OFFENSIVE)
}

pub fn pii() {}

// https://github.com/finnbear/rustrict
pub fn profanity() {
    let censored: String = "hello".chars().censor().collect();
    println!("{}", censored);
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

pub fn scan_content(erratas_job: &mut ErratasJob) -> Result<&mut ErratasJob, Box<dyn Error>> {
    let gray_image = preprocess(&erratas_job.file_info.contents)?;
    let mut ocr = Tesseract::new(None, Some("eng"))?;
    let frame = gray_image.as_raw();
    let width = gray_image.width() as i32;
    let height = gray_image.height() as i32;
    ocr = ocr.set_frame(frame, width, height, 1, width)?;

    let text = ocr.get_text()?;

    println!("{}", has_bad_text(&text));

    Ok(erratas_job)
}
