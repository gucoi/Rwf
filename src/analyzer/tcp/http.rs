use serde_json::{json, Value as JsonValue};

use crate::analyzer::utils::lsm::{LSMAction, LSMRun, LineStateMachine};
use crate::AnalyzerInterface::PropUpdate;
use crate::AnalyzerInterface::PropUpdateType;
use crate::AnalyzerInterface::TCPStream;
use crate::AnalyzerInterface::{new_prop_map, Logger, PropMap};
use crate::ByteBuffer::ByteBuffer;

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
    req_lsm: LineStateMachine<Self>,
    req_done: bool,

    resp_map: PropMap,
    resp_updated: bool,
    resp_buf: ByteBuffer,
    resp_lsm: LineStateMachine<Self>,
    resp_done: bool,
}

impl TCPStream for HTTPStream {
    fn feed(
        &mut self,
        rev: bool,
        _start: bool,
        _end: bool,
        skip: i32,
        data: &[u8],
    ) -> Option<crate::AnalyzerInterface::PropUpdate> {
        if skip != 0 {
            return None;
        }
        if data.len() == 0 {
            return None;
        }
        let mut update;
        if rev {
            self.resp_buf.append(data);
            self.resp_updated = false;
            let (_, done) = LSMRun(&mut self.resp_lsm, self);
            self.resp_done = done;
            if self.resp_updated {
                update = PropUpdate::new(&PropUpdateType::Merge, &mut self.resp_map.unwrap());
                self.resp_updated = false;
            }
        } else {
            self.req_buf.append(data);
            self.req_updated = false;
            let (_, done) = LSMRun(&mut self.req_lsm, self);
            self.req_done = done;
            if self.req_updated {
                update = PropUpdate::new(&PropUpdateType::Merge, &mut self.req_map.unwrap());
                self.req_updated = false;
            }
        }
        Some(update)
    }
    fn close(&mut self, limited: bool) -> Option<crate::AnalyzerInterface::PropUpdate> {
        self.req_buf.reset();
        self.resp_buf.reset();
        self.req_map = None;
        self.resp_map = None;
        return None;
    }
}

fn parse_request_line(stream: &mut HTTPStream) -> LSMAction {
    match stream.req_buf.get_until(b"\r\n", true, true) {
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

            stream.req_map = new_prop_map(json!({
                "method": method,
                "path": path,
                "version": version,
            }));

            stream.req_updated = true;
            return LSMAction::Next;
        }
        None => LSMAction::Pause,
    }
}

pub fn parse_request_headers(stream: &mut HTTPStream) -> LSMAction {
    let (action, header_map) = parse_headers(&mut stream.req_buf);

    if action == LSMAction::Next {
        if let Some(req_map) = stream.req_map.as_mut() {
            req_map["headers"] = header_map.unwrap_or(JsonValue::Null);
        }
        stream.req_updated = true;
    }
    action
}

fn prase_response_header(stream: &mut HTTPStream) -> LSMAction {
    let (action, header_map) = parse_headers(&mut stream.resp_buf);

    if action == LSMAction::Next {
        if let Some(resp_map) = stream.resp_map.as_mut() {
            resp_map["headers"] = header_map.unwrap_or(JsonValue::Null);
        }
        stream.resp_updated = true;
    }
    action
}

fn parse_response_line(stream: &mut HTTPStream) -> LSMAction {
    match stream.resp_buf.get_until(b"\r\n", true, true) {
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

            stream.req_map = new_prop_map(json!({
                "status": status,
                "version": version,
            }));

            stream.req_updated = true;
            return LSMAction::Next;
        }
        None => LSMAction::Pause,
    }
}

fn parse_response_header(stream: &mut HTTPStream) -> LSMAction {
    let (action, header_map) = parse_headers(&mut stream.resp_buf);
    action
}

pub fn parse_headers(buf: &mut ByteBuffer) -> (LSMAction, PropMap) {
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
    let mut prop_map = None;

    for line in content.split("\r\n") {
        let content_vec: Vec<&str> = line.splitn(2, ":").collect();
        if content_vec.len() < 2 {
            return (LSMAction::Cancel, None);
        }

        let key = content_vec[0].trim();
        let value = content_vec[1].trim();

        if prop_map.is_none() {
            prop_map = new_prop_map(json!({ key: value }));
        } else {
            if let Some(prop_map) = prop_map.as_mut() {
                prop_map[key] = json!(value);
            }
        }
    }

    (LSMAction::Next, prop_map)
}

impl HTTPStream {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        HTTPStream {
            logger: logger,
            req_buf: ByteBuffer::new(),
            req_map: None,
            req_updated: false,
            req_lsm: LineStateMachine::new(vec![
                Box::new(parse_request_line),
                Box::new(parse_request_headers),
            ]),
            req_done: false,
            resp_buf: ByteBuffer::new(),
            resp_map: None,
            resp_updated: false,
            resp_lsm: LineStateMachine::new(vec![
                Box::new(parse_response_line),
                Box::new(parse_response_header),
            ]),
            resp_done: false,
        }
    }
}
