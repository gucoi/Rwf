use crate::AnalyzerInterface::Logger;
use crate::IOInterface::{Verdict, VerdictType};
use crate::RulesetInterface::Ruleset;
use std::sync::Mutex;

type UDPVerdictType = VerdictType;

pub struct UDPContext {
    verdict: Verdict,
    packet: [u8],
}

pub struct UDPStreamFactory<T>
where
    T: Ruleset,
{
    worker_id: i32,
    logger: Box<dyn Logger>,

    ruleset_mutex: Mutex<T>,
    ruleset: T,
}

impl<T> UDPStreamFactory<T>
where
    T: Ruleset,
{
    pub fn new() {}
}
