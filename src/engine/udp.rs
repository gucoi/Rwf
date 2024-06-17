use crate::AnalyzerInterface::Logger;
use crate::IOInterface::{Verdict, VerdictType};
use crate::RulesetInterface::Ruleset;
use std::sync::Mutex;

type UDPVerdictType = VerdictType;

pub struct UDPContext {
    verdict: Verdict,
    packet: [u8],
}

pub struct UDPStreamFactory {
    worker_id: i32,

    ruleset_mutex: Mutex<Box<dyn Ruleset>>,
    ruleset: dyn Ruleset,
}

impl UDPStreamFactory {
    pub fn new() {}
}
