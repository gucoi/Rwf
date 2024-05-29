use crate::AnalyzerInterface::{
    new_prop_map, Logger, PropMap, PropUpdate, PropUpdateType, TCPStream,
};
use crate::ByteBuffer::ByteBuffer;
use crate::LSM::{LSMAction, LSMRun, LineStateMachine};
use serde_json::{json, Value as JsonValue};
use std::mem;

pub struct SSHAnalyzer {}

impl SSHAnalyzer {
    pub fn name() -> String {
        "ssh".to_string()
    }

    pub fn limit() -> u32 {
        1084
    }

    pub fn new_tcp(Logger: Box<dyn Logger>) {}
}

pub struct SSHStream {
    logger: Box<dyn Logger>,
    client_buf: ByteBuffer,
    client_map: PropMap,
    client_update: bool,
    client_lsm: LineStateMachine<Self>,
    client_done: bool,

    server_buf: ByteBuffer,
    server_map: PropMap,
    server_update: bool,
    server_lsm: LineStateMachine<Self>,
    server_done: bool,
}

fn parse_client_exchange_line(stream: &mut SSHStream) -> LSMAction {
    let (action, s_map) = parse_exchange_line(&mut stream.client_buf);

    if action == LSMAction::Next {
        stream.client_map = s_map;
        stream.client_update = true;
    }
    action
}

fn parse_server_exchange_line(stream: &mut SSHStream) -> LSMAction {
    let (action, smap) = parse_exchange_line(&mut stream.server_buf);
    if action == LSMAction::Next {
        stream.server_map = smap;
        stream.server_update = true;
    }
    action
}

fn parse_exchange_line<'a>(buf: &'a mut ByteBuffer) -> (LSMAction, PropMap) {
    match buf.get_until(b"\r\n", true, true) {
        Some(value) => {
            let value_str = match String::from_utf8(value.to_vec()) {
                Ok(s) => s,
                Err(_) => return (LSMAction::Cancel, None),
            };

            if !value_str.starts_with("SSH-") {
                return (LSMAction::Cancel, None);
            }

            let content = &value_str[..value_str.len() - 2];

            let content_vec: Vec<&str> = content.split_whitespace().collect();

            if content_vec.len() < 1 || content_vec.len() > 2 {
                return (LSMAction::Cancel, None);
            }

            let ssh_content: Vec<&str> = content_vec[0].splitn(3, "-").collect();

            if ssh_content.len() != 3 {
                return (LSMAction::Cancel, None);
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
            (LSMAction::Next, smap)
        }
        None => {
            return (LSMAction::Pause, None);
        }
    }
}

impl SSHStream {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        SSHStream {
            logger: logger,
            client_buf: ByteBuffer::new(),
            client_map: None,
            client_update: false,
            client_lsm: LineStateMachine::new(vec![Box::new(parse_client_exchange_line)]),
            client_done: false,

            server_buf: ByteBuffer::new(),
            server_map: None,
            server_update: false,
            server_lsm: LineStateMachine::new(vec![Box::new(parse_server_exchange_line)]),
            server_done: false,
        }
    }
}

impl TCPStream for SSHStream {
    fn feed(
        &mut self,
        rev: bool,
        start: bool,
        end: bool,
        skip: i32,
        data: &[u8],
    ) -> Option<PropUpdate> {
        if skip != 0 {
            return None;
        }

        if data.is_empty() {
            return None;
        }
        let mut update = None;
        if rev {
            self.server_buf.append(data);
            self.server_update = false;
            let (_, _server_done) = LSMRun(&mut self.server_lsm, self);
            self.server_done = _server_done;

            if self.server_update {
                update = Some(PropUpdate::new(
                    &PropUpdateType::Merge,
                    &mut mem::replace(
                        &mut new_prop_map(json!({"server": self.server_map}))
                            .unwrap()
                            .into(),
                        JsonValue::Null,
                    ),
                ));
                self.server_update = false;
            }
        } else {
            self.client_buf.append(data);
            self.client_update = false;
            let (_, _client_done) = LSMRun(&mut self.client_lsm, self);

            if self.client_update {
                update = Some(PropUpdate::new(
                    &PropUpdateType::Merge,
                    &mut mem::replace(
                        &mut new_prop_map(json!({"client": self.client_map}))
                            .unwrap()
                            .into(),
                        JsonValue::Null,
                    ),
                ));
                self.client_update = false;
            }
        }
        update
    }

    fn close(&mut self, limited: bool) -> Option<PropUpdate> {
        self.client_buf.reset();
        self.server_buf.reset();
        self.client_map = None;
        self.server_map = None;

        None
    }
}
