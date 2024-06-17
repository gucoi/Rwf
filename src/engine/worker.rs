use std::sync::mpsc;

pub struct WorkerPacket {
    stream_id: i32,
}

pub struct Worker {
    id: i32,
    pack_chan_sender: mpsc::Sender<WorkerPacket>,
    pack_chan_reciver: mpsc::Receiver<WorkerPacket>,

    tcp_stream_factory: Box<dyn TCPStreamFactory>,
}
