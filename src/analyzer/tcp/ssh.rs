use crate::AnalyzerInterface::{
    new_prop_map, Logger, PropMap, PropUpdate, PropUpdateType, TCPStream,
};
use crate::ByteBuffer::ByteBuffer;
use crate::LSM::{LSMAction, LineStateMachine};
use serde_json::{json, Value as JsonValue};
use std::borrow::BorrowMut;
use std::cell::RefCell;
use std::rc::Rc;

pub struct SSHAnalyzer {}

impl SSHAnalyzer {
    pub fn name() -> String {
        "ssh".to_string()
    }

    pub fn limit() -> u32 {
        1084
    }

    pub fn new_tcp(_logger: Box<dyn Logger>) {}
}

pub struct SSHStream {
    logger: Box<dyn Logger>,
    client_buf: ByteBuffer,
    client_map: PropMap,
    client_update: bool,
    client_lsm: Rc<RefCell<LineStateMachine<Self>>>,
    client_done: bool,

    server_buf: ByteBuffer,
    server_map: PropMap,
    server_update: bool,
    server_lsm: Rc<RefCell<LineStateMachine<Self>>>,
    server_done: bool,
}

impl SSHStream {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        Self {
            logger,
            client_buf: ByteBuffer::new(),
            client_map: None,
            client_update: false,
            client_lsm: Rc::new(RefCell::new(LineStateMachine::new(vec![Box::new(
                parse_client_exchange_line,
            )]))),
            client_done: false,

            server_buf: ByteBuffer::new(),
            server_map: None,
            server_update: false,
            server_lsm: Rc::new(RefCell::new(LineStateMachine::new(vec![Box::new(
                parse_server_exchange_line,
            )]))),
            server_done: false,
        }
    }
}

impl TCPStream for SSHStream {
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

        let (buf, update_flag, lsm, done_flag, map_key) = if rev {
            (
                &mut self.server_buf,
                &mut self.server_update,
                Rc::clone(&self.server_lsm),
                &mut self.server_done,
                "server",
            )
        } else {
            (
                &mut self.client_buf,
                &mut self.client_update,
                Rc::clone(&self.client_lsm),
                &mut self.client_done,
                "client",
            )
        };

        buf.append(data);
        *update_flag = false;
        let mut lsm = lsm.borrow_mut();
        let (_, done) = lsm.lsm_run(self);
        *done_flag = done;

        if *update_flag {
            let map = if rev {
                &self.server_map
            } else {
                &self.client_map
            };
            Some(PropUpdate::new(
                PropUpdateType::Merge,
                &mut mem::replace(
                    &mut new_prop_map(json!({ map_key: map })).unwrap().into(),
                    JsonValue::Null,
                ),
            ))
        } else {
            None
        }
    }

    fn close(&mut self, _limited: bool) -> Option<PropUpdate> {
        self.client_buf.reset();
        self.server_buf.reset();
        self.client_map = None;
        self.server_map = None;
        None
    }
}

fn parse_client_exchange_line(stream: &mut SSHStream) -> LSMAction {
    parse_exchange_line(
        &mut stream.client_buf,
        &mut stream.client_map,
        &mut stream.client_update,
    )
}

fn parse_server_exchange_line(stream: &mut SSHStream) -> LSMAction {
    parse_exchange_line(
        &mut stream.server_buf,
        &mut stream.server_map,
        &mut stream.server_update,
    )
}

fn parse_exchange_line<'a>(
    buf: &'a mut ByteBuffer,
    map: &mut PropMap,
    update_flag: &mut bool,
) -> LSMAction {
    match buf.get_until(b"\r\n", true, true) {
        Some(value) => {
            let value_str = match String::from_utf8(value.to_vec()) {
                Ok(s) => s,
                Err(_) => return LSMAction::Cancel,
            };

            if !value_str.starts_with("SSH-") {
                return LSMAction::Cancel;
            }

            let content = &value_str[..value_str.len() - 2];
            let content_vec: Vec<&str> = content.split_whitespace().collect();

            if content_vec.len() < 1 || content_vec.len() > 2 {
                return LSMAction::Cancel;
            }

            let ssh_content: Vec<&str> = content_vec[0].splitn(3, "-").collect();
            if ssh_content.len() != 3 {
                return LSMAction::Cancel;
            }

            let mut smap = new_prop_map(json!({
                "protocol": ssh_content[1],
                "software": ssh_content[2],
            }));

            if content_vec.len() == 2 {
                if let Some(smap) = smap.as_mut() {
                    smap["comments"] = json!(content_vec[1]);
                }
            }

            *map = smap;
            *update_flag = true;
            LSMAction::Next
        }
        None => LSMAction::Pause,
    }
}
