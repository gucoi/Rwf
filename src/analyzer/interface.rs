use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;

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

    // fn get_server_lsm<T>(&mut self) -> LineStateMachine<T>;
    // fn get_client_lsm<T>(&mut self) -> LineStateMachine<T>;
    // fn get_rev() -> bool;
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

    // fn get_server_lsm<T>() -> LineStateMachine<T>;
    // fn get_client_lsm<T>() -> LineStateMachine<T>;
    // fn get_rev() -> bool;
}

pub trait UDPAnalyzer<T, U>: Analyzer
where
    T: UDPStream,
    U: Logger,
{
    fn new_udp(info: UDPInfo, logger: U) -> T;
}

pub struct CombinedPropMap(HashMap<String, Rc<RefCell<PropMap>>>);
pub type PropMap = Option<JsonValue>;

pub fn new_prop_map(value: JsonValue) -> PropMap {
    Some(value).filter(|v| !v.is_null())
}

pub fn get_from_prop_map(mp: PropMap, key: &str) -> Option<JsonValue> {
    if let Some(prop_map) = mp {
        return prop_map.get(key).cloned();
    }
    None
}

impl Iterator for CombinedPropMap {
    type Item = (String, Rc<RefCell<PropMap>>);
    fn next(&mut self) -> Option<Self::Item> {
        let mut iter = self.0.iter_mut();
        iter.next()
            .map(|(key, prop_map)| (key.clone(), Rc::clone(prop_map)))
    }
}

impl CombinedPropMap {
    pub fn new() -> Self {
        CombinedPropMap(HashMap::new())
    }

    pub fn get(&self, an: &str, key: &str) -> PropMap {
        if let Some(value) = self.0.get(an) {
            let value = value.borrow();
            if let Some(value) = value.as_ref() {
                return value.get(key).cloned();
            }
        }
        None
    }

    pub fn iter(&self) -> impl Iterator<Item = (String, Rc<RefCell<PropMap>>)> {
        self.0
            .iter()
            .map(|(key, prop_map)| (key.clone(), Rc::clone(prop_map)))
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
    pub fn new(_prop_type: PropUpdateType, map: &JsonValue) -> Self {
        PropUpdate {
            prop_type: _prop_type,
            m: map.clone(),
        }
    }
}
