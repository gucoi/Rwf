use crate::AnalyzerInterface::{
    new_prop_map, Logger, PropMap, PropUpdate, PropUpdateType, TCPStream,
};
use crate::ByteBuffer::ByteBuffer;
use crate::LSM::{LSMAction, LSMContext, LineStateMachine};
use serde_json::{json, Value as JsonValue};

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
    client_lsm: LineStateMachine,
    client_done: bool,
    client_msg_len: usize,

    server_buf: ByteBuffer,
    server_map: PropMap,
    server_update: bool,
    server_lsm: LineStateMachine,
    server_done: bool,
    server_msg_len: usize,
}

impl SSHStream {
    pub fn new(logger: Box<dyn Logger>) -> Self {
        Self {
            logger,
            client_buf: ByteBuffer::new(),
            client_map: None,
            client_update: false,
            client_lsm: LineStateMachine::new(vec![Box::new(parse_exchange_ctx)]),
            client_done: false,
            client_msg_len: 0,

            server_buf: ByteBuffer::new(),
            server_map: None,
            server_update: false,
            server_lsm: LineStateMachine::new(vec![Box::new(parse_exchange_ctx)]),
            server_done: false,
            server_msg_len: 0,
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

        let (buf, update_flag, lsm, done_flag, map_key, map, msg_len) = if rev {
            (
                &mut self.server_buf,
                &mut self.server_update,
                &mut self.server_lsm,
                &mut self.server_done,
                "server",
                &mut self.server_map,
                &mut self.server_msg_len,
            )
        } else {
            (
                &mut self.client_buf,
                &mut self.client_update,
                &mut self.client_lsm,
                &mut self.client_done,
                "client",
                &mut self.client_map,
                &mut self.client_msg_len,
            )
        };

        let mut ctx = LSMContext::new(buf, done_flag, update_flag, map, msg_len);

        buf.append(data);
        *update_flag = false;
        let (_, done) = lsm.lsm_run(&mut ctx);
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

fn parse_exchange_ctx(ctx: &mut LSMContext) -> LSMAction {
    parse_exchange_line(&mut ctx.buf, &mut ctx.map, &mut ctx.update_flag)
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
