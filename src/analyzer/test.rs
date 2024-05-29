use std::collections::HashMap;
use std::net::SocketAddr;

pub trait Analyzer {
    fn name(&self) -> &str;
    fn limit(&self) -> i32;
}

pub trait Logger {}

pub struct TCPInfo {
    src_ip: SocketAddr,
    dst_ip: SocketAddr,
    src_port: SocketAddr,
    dst_port: u16,
}

pub trait TCPAnalyzer: Analyzer {
    fn new_tcp(&self, tcp_info: TCPInfo, logger: &dyn Logger) -> Box<dyn TCPStream>;
}

pub trait TCPStream {
    fn feed(
        &mut self,
        rev: bool,
        start: bool,
        end: bool,
        skip: i32,
        data: &[u8],
    ) -> Option<PropUpdate>;
    fn close(&self, limited: bool) -> Option<PropUpdate>;
}

pub struct PropMap(serde_json::Value);

impl PropMap {
    pub fn new(value: serde_json::Value) -> Self {
        PropMap(value)
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        let mut cur = self.0.as_ref();
        for k in key.split(".") {
            cur = cur.and_then(|m| m.get(k));
            if cur.is_none() {
                break;
            }
        }
        cur
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_null()
    }
}

pub struct CombinedPropMap(HashMap<String, PropMap>);

impl CombinedPropMap {
    pub fn new() -> Self {
        CombinedPropMap(HashMap::new())
    }

    pub fn get(&self, an: &str, key: &str) -> Option<&serde_json::Value> {
        self.0.get(an).and_then(|prop_map| prop_map.get(key))
    }

    pub fn iter(self) -> impl Iterator<Item = (String, serde_json::Value)> {
        self.0.into_iter().map(|(key, prop_map)| (key, prop_map.0))
    }
}

pub enum PropUpdateType {
    Noop,
    Merge,
    Replace,
    Delete,
}

pub struct PropUpdate {
    update_type: PropUpdateType,
    prop_map: PropMap,
}

impl PropUpdate {
    pub fn new(update_type: PropUpdateType, prop_map: PropMap) -> Self {
        PropUpdate {
            update_type,
            prop_map,
        }
    }
}

