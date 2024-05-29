use crate::IOInterface::PakcetIO;
use crate::RulesetInterface::{Action, Ruleset, StreamInfo};
use std::error::Error;
// use std::io::Error;

pub trait Engine {
    fn update_ruleset(ruleset: dyn Ruleset);
    fn run();
}

pub struct Config {
    logger: Box<dyn Logger>,
    io: Vec<Box<dyn PakcetIO>>,

    rule_set: Box<dyn Ruleset>,
    workers: i32,
    worker_queue_size: i32,
    worker_tcp_max_buffered_pages_total: i32,
    worker_tcp_max_buffered_pages_conn: i32,
    worker_udp_max_streams: i32,
}

impl Config {
    pub fn get_workers(&self) -> i32 {
        self.workers
    }
}

pub trait Logger {
    fn worker_start(&self, id: i32);
    fn worker_stop(&self, id: i32);
    fn tcp_stream_new(&self, worker_id: i32, info: StreamInfo);
    fn tcp_stream_prop_update(&self, info: StreamInfo, close: bool);
    fn tcp_stream_action(&self, info: StreamInfo, action: Action, no_match: bool);

    fn udp_stream_new(&self, worker_id: i32, info: StreamInfo);
    fn udp_stream_prop_update(&self, info: StreamInfo, close: bool);
    fn udp_stream_action(&self, info: StreamInfo, action: Action, no_match: bool);

    fn match_error(&self, info: StreamInfo, err: dyn Error);
    fn modify_error(&self, info: StreamInfo, err: dyn Error);

    fn analyzer_debugf(
        &self,
        stream_id: i32,
        name: &str,
        format: &str,
        args: &[&dyn std::fmt::Debug],
    );
    fn analyzer_infof(
        &self,
        stream_id: i32,
        name: &str,
        format: &str,
        args: &[&dyn std::fmt::Debug],
    );
    fn analyzer_errorf(
        &self,
        stream_id: i32,
        name: &str,
        format: &str,
        args: &[&dyn std::fmt::Debug],
    );
}
