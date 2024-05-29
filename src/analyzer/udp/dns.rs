use crate::AnalyzerInterface::{Logger, PropMap, PropUpdate, PropUpdateType, TCPStream, UDPStream};
use crate::ByteBuffer::ByteBuffer;
use crate::LSM::{LSMAction, LSMRun, LineStateMachine};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use trust_dns_proto::{
    op::{Message, MessageType, Query},
    rr::RData,
};
pub struct DNSAnalyzer {}

impl DNSAnalyzer {
    pub fn name(&self) -> &str {
        "dns"
    }
    pub fn limit(&self) -> i32 {
        0
    }
}

pub struct DNSTCPStream {
    logger: Box<dyn Logger>,
    req_buf: ByteBuffer,
    req_map: PropMap,
    req_update: bool,
    req_lsm: LineStateMachine<Self>,
    req_done: bool,

    resp_buf: ByteBuffer,
    resp_map: PropMap,
    resp_update: bool,
    resp_lsm: LineStateMachine<Self>,
    resp_done: bool,

    req_msg_len: usize,
    resp_msg_len: usize,
}

pub struct DNSUDPStream {}

impl TCPStream for DNSTCPStream {
    fn feed(
        &mut self,
        rev: bool,
        _start: bool,
        _end: bool,
        skip: i32,
        data: &[u8],
    ) -> Option<PropUpdate> {
        if skip != 0 {
            return None;
        }
        if data.is_empty() {
            return None;
        }
        let mut update;
        if rev {
            self.resp_buf.append(data);
            self.resp_update = false;
            let (_, done) = LSMRun(&mut self.resp_lsm, self);
            self.resp_done = done;
            if self.resp_update {
                update = PropUpdate::new(PropUpdateType::Replace, self.resp_map);
                self.resp_update = false;
            }
        } else {
            self.req_buf.append(data);
            self.req_update = false;
            let (_, done) = LSMRun(&mut self.req_lsm, self);
            self.req_done = done;

            if self.req_update {
                update = PropUpdate::new(&PropUpdateType::Replace, self.req_map.as_mut().unwrap());
                self.req_update = false;
            }
        }

        Some(update)
    }

    fn close(&mut self, limited: bool) -> Option<PropUpdate> {
        None
    }
}

impl UDPStream for DNSUDPStream {
    fn feed(&mut self, rev: bool, data: &[u8]) -> Option<PropUpdate> {
        None
    }

    fn close(limited: bool) -> Option<PropUpdate> {
        None
    }
}

fn get_req_message_len(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.req_buf.get(2, true) {
        stream.req_msg_len = (data[0] << 8 | data[1]) as usize;
        return LSMAction::Next;
    }
    LSMAction::Pause
}

fn get_req_message(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.req_buf.get(stream.resp_msg_len, true) {
        let m = parse_dns_message(&data);
        if m.is_none() {
            return LSMAction::Cancel;
        }
        stream.req_map = m;
        stream.req_done = true;
        LSMAction::Reset
    } else {
        LSMAction::Pause
    }
}

fn get_resp_message_len(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.resp_buf.get(2, true) {
        stream.resp_msg_len = (data[0] << 8 | data[1]) as usize;
        return LSMAction::Next;
    }
    LSMAction::Pause
}

fn get_resp_message(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.resp_buf.get(stream.resp_msg_len, true) {
        let m = parse_dns_message(&data);
        if m.is_none() {
            return LSMAction::Cancel;
        }
        stream.resp_map = m;
        stream.resp_update = true;
        LSMAction::Reset
    } else {
        LSMAction::Pause
    }
}

fn parse_dns_message(data: &[u8]) -> PropMap {
    let dns = Message::from_vec(data).unwrap();
    let header = dns.header();

    let mut m = json!({
        "id": header.id().to_string(),
        "qr": header.message_type() == MessageType::Response,
        "opcode": header.op_code().to_string(),
        "aa": header.authoritative().to_string(),
        "tc": header.truncated().to_string(),
        "rd": header.recursion_desired().to_string(),
        "ra": header.recursion_available().to_string(),
        "rcode": header.response_code().to_string(),
    });

    if !dns.queries().is_empty() {
        let queries = dns
            .queries()
            .iter()
            .map(|q| query_to_propmap(q))
            .collect::<Vec<Value>>();
        m["questions"] = json!(queries);
    }

    if !dns.answers().is_empty() {
        let answers = dns
            .answers()
            .iter()
            .map(|rr| rr_to_propmap(rr))
            .collect::<Vec<Value>>();
        m["answers"] = json!(answers);
    }

    if !dns.additionals().is_empty() {
        let additional = dns
            .additionals()
            .iter()
            .map(|rr| rr_to_propmap(rr))
            .collect::<Vec<Value>>();
    }

    Some(m)
}

fn query_to_propmap(q: &Query) -> Value {
    json!({
        "name": q.name().to_string(),
        "type": q.query_type().to_string(),
        "class": q.query_class().to_string(),
    })
}

fn rr_to_propmap(rr: &trust_dns_proto::rr::Record) -> Value {
    let mut m = json!({
        "name": rr.name().to_string(),
        "type": rr.record_type().to_string(),
        "class": rr.dns_class().to_string(),
        "ttl": rr.ttl().to_string(),
    });

    match rr.into_data().unwrap() {
        RData::A(addr) => {
            m["address"] = json!(Ipv4Addr::from(*addr).to_string());
        }
        RData::AAAA(addr) => {
            m["address"] = json!(Ipv6Addr::from(*addr).to_string());
        }
        RData::NS(ns) => {
            m["ns"] = json!(ns.to_string());
        }
        RData::CNAME(cname) => {
            m["cname"] = json!(cname.to_string());
        }
        RData::PTR(ptr) => {
            m["ptr"] = json!(ptr.to_string());
        }
        RData::TXT(txt) => {
            m["txt"] = json!(txt.to_string());
        }
        RData::MX(mx) => {
            m["mx"] = json!(mx.exchange().to_string());
        }
        _ => {}
    }
    m
}

impl DNSTCPStream {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        DNSTCPStream {
            logger: logger,
            req_buf: ByteBuffer::new(),
            resp_buf: ByteBuffer::new(),
            req_lsm: LineStateMachine::new(vec![
                Box::new(get_req_message_len),
                Box::new(get_req_message),
            ]),
            resp_lsm: LineStateMachine::new(vec![
                Box::new(get_resp_message_len),
                Box::new(get_resp_message),
            ]),
            req_map: None,
            resp_map: None,
            req_done: false,
            resp_done: false,
            resp_msg_len: 0,
            req_msg_len: 0,
            req_update: false,
            resp_update: false,
        }
    }
}
