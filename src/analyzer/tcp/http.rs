use serde_json::{json, Value as JsonValue};

use crate::analyzer::utils::lsm::{LSMAction, LineStateMachine};
use crate::AnalyzerInterface::PropUpdate;
use crate::AnalyzerInterface::PropUpdateType;
use crate::AnalyzerInterface::TCPStream;
use crate::AnalyzerInterface::{new_prop_map, Logger, PropMap};
use crate::ByteBuffer::ByteBuffer;
use crate::LSM::LSMContext;

pub struct HTTPAnalyzer {}

impl HTTPAnalyzer {
    fn name(&self) -> String {
        "http".to_string()
    }

    fn limit(&self) -> i32 {
        8192
    }
}

pub struct HTTPStream {
    logger: Box<dyn Logger>,

    req_map: PropMap,
    req_updated: bool,
    req_buf: ByteBuffer,
    req_lsm: LineStateMachine,
    req_done: bool,
    req_msg_len: usize,

    resp_map: PropMap,
    resp_updated: bool,
    resp_buf: ByteBuffer,
    resp_lsm: LineStateMachine,
    resp_done: bool,
    resp_msg_len: usize,
}

impl HTTPStream {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        HTTPStream {
            logger,
            req_buf: ByteBuffer::new(),
            req_map: None,
            req_updated: false,
            req_lsm: LineStateMachine::new(vec![
                Box::new(parse_request_line),
                Box::new(parse_request_headers),
            ]),
            req_done: false,
            req_msg_len: 0,
            resp_buf: ByteBuffer::new(),
            resp_map: None,
            resp_updated: false,
            resp_lsm: LineStateMachine::new(vec![
                Box::new(parse_response_line),
                Box::new(parse_response_headers),
            ]),
            resp_done: false,
            resp_msg_len: 0,
        }
    }
}

impl TCPStream for HTTPStream {
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

        let (buf, updated, lsm, done, map, msg_len) = if rev {
            (
                &mut self.resp_buf,
                &mut self.resp_updated,
                &mut self.resp_lsm,
                &mut self.resp_done,
                &mut self.resp_map,
                &mut self.resp_msg_len,
            )
        } else {
            (
                &mut self.req_buf,
                &mut self.req_updated,
                &mut self.req_lsm,
                &mut self.req_done,
                &mut self.req_map,
                &mut self.req_msg_len,
            )
        };

        buf.append(data);
        *updated = false;
        let mut ctx = LSMContext::new(buf, done, updated, map, msg_len);
        let (_, done_flag) = lsm.lsm_run(&mut ctx);
        *done = done_flag;

        if *updated {
            Some(PropUpdate::new(
                PropUpdateType::Merge,
                map.as_ref().unwrap(),
            ))
        } else {
            None
        }
    }

    fn close(&mut self, _limited: bool) -> Option<PropUpdate> {
        self.req_buf.reset();
        self.resp_buf.reset();
        self.req_map = None;
        self.resp_map = None;
        None
    }
}

fn parse_request_line(ctx: &mut LSMContext) -> LSMAction {
    match ctx.buf.get_until(b"\r\n", true, true) {
        Some(value) => {
            let value_str = match String::from_utf8(value.to_vec()) {
                Ok(s) => s,
                Err(_) => return LSMAction::Cancel,
            };

            let content = &value_str[..value_str.len() - 2];
            let content_vec: Vec<&str> = content.split_whitespace().collect();
            if content_vec.len() != 3 {
                return LSMAction::Cancel;
            }
            let method = content_vec[0];
            let path = content_vec[1];
            let version = content_vec[2];

            if !version.starts_with("HTTP/") {
                return LSMAction::Cancel;
            }

            *ctx.map = new_prop_map(json!({
                "method": method,
                "path": path,
                "version": version,
            }));

            *ctx.update_flag = true;
            LSMAction::Next
        }
        None => LSMAction::Pause,
    }
}

fn parse_request_headers(ctx: &mut LSMContext) -> LSMAction {
    let (action, header_map) = parse_headers(&mut ctx.buf);

    if action == LSMAction::Next {
        if let Some(req_map) = ctx.map.as_mut() {
            req_map["headers"] = header_map.unwrap_or(JsonValue::Null);
        }
        *ctx.update_flag = true;
    }
    action
}

fn parse_response_line(ctx: &mut LSMContext) -> LSMAction {
    match ctx.buf.get_until(b"\r\n", true, true) {
        Some(value) => {
            let value_str = match String::from_utf8(value.to_vec()) {
                Ok(s) => s,
                Err(_) => return LSMAction::Cancel,
            };

            let content = &value_str[..value_str.len() - 2];
            let content_vec: Vec<&str> = content.split_whitespace().collect();
            if content_vec.len() < 2 {
                return LSMAction::Cancel;
            }

            let version = content_vec[0];
            let status: i32 = content_vec[1].parse().unwrap_or(-1);
            if !version.starts_with("HTTP/") || status == 0 {
                return LSMAction::Cancel;
            }

            *ctx.map = new_prop_map(json!({
                "status": status,
                "version": version,
            }));

            *ctx.update_flag = true;
            LSMAction::Next
        }
        None => LSMAction::Pause,
    }
}

fn parse_response_headers(ctx: &mut LSMContext) -> LSMAction {
    let (action, header_map) = parse_headers(&mut ctx.buf);

    if action == LSMAction::Next {
        if let Some(resp_map) = ctx.map.as_mut() {
            resp_map["headers"] = header_map.unwrap_or(JsonValue::Null);
        }
        *ctx.update_flag = true;
    }
    action
}

fn parse_headers(buf: &mut ByteBuffer) -> (LSMAction, PropMap) {
    let headers = match buf.get_until(b"\r\n\r\n", true, true) {
        Some(headers) => headers,
        None => return (LSMAction::Pause, None),
    };

    let content = match String::from_utf8(headers.to_vec()) {
        Ok(content) => content,
        Err(_) => return (LSMAction::Pause, None),
    };

    if content.len() <= 4 {
        return (LSMAction::Pause, None);
    }

    let content = &content[..content.len() - 2];
    let mut prop_map = new_prop_map(json!({}));

    for line in content.split("\r\n") {
        let content_vec: Vec<&str> = line.splitn(2, ":").collect();
        if content_vec.len() < 2 {
            return (LSMAction::Cancel, None);
        }

        let key = content_vec[0].trim();
        let value = content_vec[1].trim();

        if let Some(prop_map) = prop_map.as_mut() {
            prop_map[key] = json!(value);
        }
    }

    (LSMAction::Next, prop_map)
}
