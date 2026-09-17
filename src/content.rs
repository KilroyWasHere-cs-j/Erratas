use rustrict::CensorIter;

// TODO: Scan PII patterns for regex matches.

// TODO: Scan profanity patterns for word-list matches.

pub fn pii() {}

// https://github.com/finnbear/rustrict
pub fn profanity() {
    let censored: String = "hello".chars().censor().collect();
    println!("{}", censored);
}

