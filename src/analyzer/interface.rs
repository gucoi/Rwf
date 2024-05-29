use serde_json::Value as JsonValue;
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
    src_port: u16,
    dst_port: u16,
}

pub trait TCPAnalyzer: Analyzer {
    fn new_tcp(&self, tcp_info: TCPInfo, logger: Box<dyn Logger>) -> Self;
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
    fn close(&mut self, limited: bool) -> Option<PropUpdate>;
}

pub struct UDPInfo {
    src_ip: SocketAddr,
    dst_ip: SocketAddr,
    src_port: u16,
    dst_port: u16,
}

pub trait UDPStream {
    fn feed(&mut self, rev: bool, data: &[u8]) -> Option<PropUpdate>;
    fn close(limited: bool) -> Option<PropUpdate>;
}

pub trait UDPAnalyzer<T: UDPStream, U: Logger>: Analyzer {
    fn new_udp(info: UDPInfo, logger: U) -> T;
}

pub struct CombinedPropMap<'a>(HashMap<String, &'a PropMap>);
pub type PropMap = Option<JsonValue>;

pub fn new_prop_map(value: JsonValue) -> PropMap {
    Some(value).filter(|v| !v.is_null())
}

pub fn get_from_prop_map<'a>(mp: &'a PropMap, key: &str) -> Option<&'a JsonValue> {
    mp.as_ref().and_then(|value| {
        let pointer = format!("/{}", key.replace(".", "/"));
        value.pointer(&pointer)
    })
}

impl<'a> Iterator for CombinedPropMap<'a> {
    type Item = (String, &'a serde_json::Value);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.iter().next().map(|(key, prop_map)| {
            let value = prop_map.as_ref().unwrap();
            (key.clone(), value)
        })
    }
}

impl<'a> CombinedPropMap<'a> {
    pub fn new() -> Self {
        CombinedPropMap(HashMap::new())
    }

    pub fn get(&self, an: &str, key: &str) -> Option<&serde_json::Value> {
        match self.0.get(an).unwrap() {
            Some(value) => value.get(key),
            None => None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (String, &serde_json::Value)> {
        self.0
            .iter()
            .map(|(key, prop_map)| (key.clone(), prop_map.as_ref().unwrap()))
    }
}

pub enum PropUpdateType {
    None,
    Merge,
    Replace,
    Delete,
}

pub struct PropUpdate {
    prop_type: PropUpdateType,
    m: JsonValue,
}

impl PropUpdate {
    pub fn new(_prop_type: PropUpdateType, map: JsonValue) -> Self {
        PropUpdate {
            prop_type: _prop_type,
            m: map,
        }
    }
}
