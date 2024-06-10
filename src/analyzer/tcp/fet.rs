use crate::AnalyzerInterface::{new_prop_map, Logger, PropUpdate, PropUpdateType, TCPStream};
use serde_json::json;

pub struct FETAnalyzer {}

impl FETAnalyzer {
    fn name(&self) -> &str {
        "fet"
    }

    fn limit(&self) -> i32 {
        8192
    }

    fn new_tcp<T: Logger>(&self, logger: T) -> FetStream<T> {
        FetStream::new(logger)
    }
}

pub struct FetStream<T: Logger> {
    logger: T,
}

impl<T: Logger> FetStream<T> {
    fn new(logger: T) -> Self {
        FetStream { logger }
    }
}

impl<T: Logger> TCPStream for FetStream<T> {
    fn feed(
        &mut self,
        _rev: bool,
        _start: bool,
        _end: bool,
        skip: i32,
        data: &[u8],
    ) -> Option<PropUpdate> {
        if skip != 0 || data.is_empty() {
            return None;
        }

        let ex1 = average_pop_count(data);
        let ex2 = is_first_six_printable(data);
        let ex3 = printable_percentage(data);
        let ex4 = contiguous_printable(data);
        let ex5 = is_tls_or_http(data);

        let exempt = (ex1 <= 3.4 || ex1 >= 4.6) || ex2 || ex3 > 0.5 || ex4 > 20 || ex5;
        Some(PropUpdate::new(
            PropUpdateType::Replace,
            new_prop_map(json!({
                "ex1": ex1,
                "ex2": ex2,
                "ex3": ex3,
                "ex4": ex4,
                "ex5": ex5,
                "yes": !exempt
            }))
            .as_ref()
            .unwrap(),
        ))
    }

    fn close(&mut self, _limited: bool) -> Option<PropUpdate> {
        None
    }
}

fn average_pop_count(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let total: u32 = bytes.iter().map(|&b| pop_count(b)).sum();
    total as f32 / bytes.len() as f32
}

fn pop_count(byte: u8) -> u32 {
    byte.count_ones()
}

fn is_first_six_printable(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && bytes.iter().take(6).all(is_printable)
}

fn printable_percentage(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let printable_count = bytes.iter().filter(|&&b| is_printable(b)).count() as f32;
    printable_count / bytes.len() as f32
}

fn is_printable(b: &u8) -> bool {
    matches!(b, 0x20..=0x7e)
}

fn contiguous_printable(bytes: &[u8]) -> u32 {
    let mut max_count = 0;
    let mut current_count = 0;

    for &byte in bytes {
        if is_printable(&byte) {
            current_count += 1;
            if current_count > max_count {
                max_count = current_count;
            }
        } else {
            current_count = 0;
        }
    }

    max_count
}

fn is_tls_or_http(bytes: &[u8]) -> bool {
    if bytes.len() < 3 {
        return false;
    }

    if bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] <= 0x03 {
        return true;
    }

    matches!(
        &bytes[..3],
        b"GET" | b"HEA" | b"POS" | b"PUT" | b"DEL" | b"CON" | b"OPT" | b"TRA" | b"PAT"
    )
}
