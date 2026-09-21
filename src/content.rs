use image::ImageReader;
use rustrict::CensorIter;
use std::error::Error;
use std::io::Cursor;

use crate::types::ErratasJob;

// TODO: Scan PII patterns for regex matches.

// TODO: Scan profanity patterns for word-list matches.

pub fn pii() {}

// https://github.com/finnbear/rustrict
pub fn profanity() {
    let censored: String = "hello".chars().censor().collect();
    println!("{}", censored);
}

fn preprocess(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let image = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()?
        .decode();
    Ok(())
}

fn scrap_text() {}

// pub fn check_text(erratas_job: &mut ErratasJob) -> ErratasJob {
//     return erratas_job;
// }
// pub fn preprocess_image(image_path: &Path) -> Result<GrayImage> {
//     let image = ImageReader::open(image_path)?.decode()?;
//     let mut gray_image = image.to_luma8();
//     let threshold = otsu_level(&gray_image);
//     threshold_mut(&mut gray_image, threshold, ThresholdType::Binary);
//     Ok(gray_image)
// }
// use anyhow::Result;
// use std::path::Path;
// use tesseract::Tesseract;

// use super::convert_image::preprocess_image;

// pub fn get_text(image_path: &Path) -> Result<String> {
//     // Initialize Tesseract for English language
//     let mut ocr = Tesseract::new(None, Some("eng"))?;

//     // Preprocess the image
//     let gray_image = preprocess_image(image_path)?;

//     // Create a temp path for the processed image
//     let temp_path = std::env::temp_dir().join("temp_processed.png");
//     let temp_path_str = temp_path.to_str().unwrap();

//     // Save the preprocessed image to a temporary file
//     gray_image.save(&temp_path_str)?;

//     // Set the image for OCR processing
//     ocr = ocr.set_image(temp_path_str)?;

//     // Retrieve the extracted text
//     let text = ocr.get_text()?;
//     return Ok(text);
// }
