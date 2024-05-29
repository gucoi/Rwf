use std::error::Error;

pub type Verdict = i32;

pub enum VerdictType {
    Accept,
    AcceptModify,
    AcceptStream,
    Drop,
    DropStream,
}

pub trait Packet {
    fn stream_id() -> u32;
    fn data() -> [u8];
}

type PacketCallback = Box<dyn Fn(dyn Packet, dyn Error) -> bool>;

pub trait PakcetIO {}
