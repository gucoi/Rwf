use clap::Error;
use serde::Serialize;

use crate::AnalyzerInterface::{Analyzer, CombinedPropMap};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;

pub enum Action {
    Maybe,
    Allow,
    Block,
    Drop,
    Modify,
}

impl Action {
    pub fn to_string(&self) -> &str {
        match self {
            Action::Maybe => "maybe",
            Action::Allow => "allow",
            Action::Block => "block",
            Action::Drop => "drop",
            Action::Modify => "modify",
            _ => "unknown",
        }
    }
}

#[derive(Serialize)]
pub enum Protocol {
    TCP,
    UDP,
}

impl Protocol {
    fn to_string(&self) -> &str {
        match self {
            Protocol::TCP => "tcp",
            Protocol::UDP => "udp",
            _ => "unknown",
        }
    }
}

pub struct StreamInfo {
    pub id: i64,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub props: CombinedPropMap,
}

impl StreamInfo {
    pub fn src_string(&self) -> String {
        format!("{}:{}", self.src_ip, self.src_port)
    }

    pub fn dst_string(&self) -> String {
        format!("{}:{}", self.dst_ip, self.dst_port)
    }
}

#[async_trait]
pub trait ModifierInstance {}

#[async_trait]
pub trait Modifier {
    async fn new_instance(args: HashMap<String, String>) -> Box<dyn ModifierInstance>;
}

#[async_trait]
pub trait Ruleset {
    fn analyzers(&self, stream_info: &StreamInfo) -> &[Box<dyn Analyzer>];
    async fn match_rule(&self, stream_info: &StreamInfo) -> MatchResult;
}

pub struct MatchResult {
    pub action: Action,
    pub mod_instance: Box<dyn ModifierInstance>,
}

pub trait Logger {
    fn log(stream_info: StreamInfo, name: String, err: Error);
    fn match_error(stream_info: StreamInfo, name: String, err: Error);
}
