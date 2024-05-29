use serde::Serialize;

use crate::AnalyzerInterface;
use std::net::IpAddr;

pub trait Ruleset {
    fn analyzers(&self, stream_info: &StreamInfo);
    fn ruleset_match(&self, stream_info: &StreamInfo);
}

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

pub struct StreamInfo<'a> {
    pub id: i64,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub props: AnalyzerInterface::CombinedPropMap<'a>,
}

impl<'a> StreamInfo<'a> {
    pub fn src_string(&self) -> String {
        format!("{}:{}", self.src_ip, self.src_port)
    }

    pub fn dst_string(&self) -> String {
        format!("{}:{}", self.dst_ip, self.dst_port)
    }
}

pub struct MatchResult {
    action: Action,
}
