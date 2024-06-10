use crate::AnalyzerInterface::{Logger, PropMap, PropUpdate, PropUpdateType, TCPStream, UDPStream};
use crate::ByteBuffer::ByteBuffer;
use crate::LSM::{LSMAction, LineStateMachine};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
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
    req_lsm: Rc<RefCell<LineStateMachine<Self>>>,
    req_done: bool,

    resp_buf: ByteBuffer,
    resp_map: PropMap,
    resp_update: bool,
    resp_lsm: Rc<RefCell<LineStateMachine<Self>>>,
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
        if skip != 0 || data.is_empty() {
            return None;
        }

        let (buf, update_flag, lsm, done_flag, map) = if rev {
            (
                &mut self.resp_buf,
                &mut self.resp_update,
                Rc::clone(&self.resp_lsm),
                &mut self.resp_done,
                &mut self.resp_map,
            )
        } else {
            (
                &mut self.req_buf,
                &mut self.req_update,
                Rc::clone(&self.req_lsm),
                &mut self.req_done,
                &mut self.req_map,
            )
        };

        buf.append(data);
        *update_flag = false;
        let mut lsm = lsm.borrow_mut();
        let (_, done) = lsm.lsm_run(self);
        *done_flag = done;

        if *update_flag {
            Some(PropUpdate::new(
                PropUpdateType::Replace,
                map.as_ref().unwrap(),
            ))
        } else {
            None
        }
    }

    fn close(&mut self, _limited: bool) -> Option<PropUpdate> {
        None
    }
}

impl UDPStream for DNSUDPStream {
    fn feed(&mut self, _rev: bool, _data: &[u8]) -> Option<PropUpdate> {
        None
    }

    fn close(_limited: bool) -> Option<PropUpdate> {
        None
    }
}

impl DNSTCPStream {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        Self {
            logger,
            req_buf: ByteBuffer::new(),
            resp_buf: ByteBuffer::new(),
            req_lsm: Rc::new(RefCell::new(LineStateMachine::new(vec![
                Box::new(get_req_message_len),
                Box::new(get_req_message),
            ]))),
            resp_lsm: Rc::new(RefCell::new(LineStateMachine::new(vec![
                Box::new(get_resp_message_len),
                Box::new(get_resp_message),
            ]))),
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

fn get_req_message_len(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.req_buf.get(2, true) {
        stream.req_msg_len = (data[0] as usize) << 8 | data[1] as usize;
        LSMAction::Next
    } else {
        LSMAction::Pause
    }
}

fn get_req_message(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.req_buf.get(stream.req_msg_len, true) {
        if let Some(m) = parse_dns_message(&data) {
            stream.req_map = m;
            stream.req_done = true;
            LSMAction::Reset
        } else {
            LSMAction::Cancel
        }
    } else {
        LSMAction::Pause
    }
}

fn get_resp_message_len(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.resp_buf.get(2, true) {
        stream.resp_msg_len = (data[0] as usize) << 8 | data[1] as usize;
        LSMAction::Next
    } else {
        LSMAction::Pause
    }
}

fn get_resp_message(stream: &mut DNSTCPStream) -> LSMAction {
    if let Some(data) = stream.resp_buf.get(stream.resp_msg_len, true) {
        if let Some(m) = parse_dns_message(&data) {
            stream.resp_map = m;
            stream.resp_update = true;
            LSMAction::Reset
        } else {
            LSMAction::Cancel
        }
    } else {
        LSMAction::Pause
    }
}

fn parse_dns_message(data: &[u8]) -> Option<PropMap> {
    let dns = Message::from_vec(data).ok()?;
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
            .map(query_to_propmap)
            .collect::<Vec<Value>>();
        m["questions"] = json!(queries);
    }

    if !dns.answers().is_empty() {
        let answers = dns
            .answers()
            .iter()
            .map(rr_to_propmap)
            .collect::<Vec<Value>>();
        m["answers"] = json!(answers);
    }

    if !dns.additionals().is_empty() {
        let additional = dns
            .additionals()
            .iter()
            .map(rr_to_propmap)
            .collect::<Vec<Value>>();
        m["additionals"] = json!(additional);
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

    match rr.data() {
        Some(RData::A(addr)) => {
            m["address"] = json!(Ipv4Addr::from(*addr).to_string());
        }
        Some(RData::AAAA(addr)) => {
            m["address"] = json!(Ipv6Addr::from(*addr).to_string());
        }
        Some(RData::NS(ns)) => {
            m["ns"] = json!(ns.to_string());
        }
        Some(RData::CNAME(cname)) => {
            m["cname"] = json!(cname.to_string());
        }
        Some(RData::PTR(ptr)) => {
            m["ptr"] = json!(ptr.to_string());
        }
        Some(RData::TXT(txt)) => {
            m["txt"] = json!(txt.to_string());
        }
        Some(RData::MX(mx)) => {
            m["mx"] = json!(mx.exchange().to_string());
        }
        _ => {}
    }
    m
}
