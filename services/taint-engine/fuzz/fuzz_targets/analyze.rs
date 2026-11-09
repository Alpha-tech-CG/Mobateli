//! Fuzz target: arbitrary bytes as a source file of each supported language.
//! Run with `-timeout=N` so a slow input is reported like a crash — for this
//! engine a stall is a bypass (the TS adapter fails open after 5 s).
#![no_main]

use libfuzzer_sys::fuzz_target;

const EXTS: &[&str] = &["js", "ts", "tsx", "py"];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let path = format!("f.{}", EXTS[selector as usize % EXTS.len()]);
    let source = String::from_utf8_lossy(rest);
    let _ = codegate_scan_engine::analyze_source(&path, &source);
});
