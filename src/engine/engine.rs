use crate::io::{Packet, PacketIO, Verdict};
use crate::ruleset::interface::Ruleset;
use crate::worker::{Worker, WorkerConfig, WorkerPacket};
use crossbeam_channel::{bounded, Receiver, Sender};
use gopacket::{DecodeOptions, LayerType, Packet};
use std::error::Error;
use std::sync::Arc;
use std::time::SystemTime;

pub struct Engine {
    logger: Logger,
    io: Arc<PacketIO>,
    workers: Vec<Worker>,
}

impl Engine {
    pub fn new(config: Config) -> Result<Engine, Box<dyn Error>> {
        let worker_count = config.workers;
        if worker_count <= 0 {
            worker_count = num_cpus::get();
        }
        let mut workers = Vec::new();
        for i in 0..worker_count {
            let worker = Worker::new(WorkerConfig {
                id: i,
                chan_size: config.worker_queue_size,
                logger: config.logger.clone(),
                ruleset: config.ruleset.clone(),
                tcp_max_buffered_pages_total: config.worker_tcp_max_buffered_pages_total,
                tcp_max_buffered_pages_per_conn: config.worker_tcp_max_buffered_pages_per_conn,
                tcp_timeout: config.worker_tcp_timeout,
                udp_max_streams: config.worker_udp_max_streams,
            })?;
            workers.push(worker);
        }
        Ok(Engine {
            logger: config.logger,
            io: Arc::new(config.io),
            workers,
        })
    }

    pub fn update_ruleset(&self, r: Ruleset) -> Result<(), Box<dyn Error>> {
        for worker in &self.workers {
            worker.update_ruleset(r.clone())?;
        }
        Ok(())
    }

    pub fn run(&self) -> Result<(), Box<dyn Error>> {
        let (tx, rx): (
            Sender<Result<(), Box<dyn Error>>>,
            Receiver<Result<(), Box<dyn Error>>>,
        ) = bounded(1);
        for worker in &self.workers {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let result = worker.run();
                tx.send(result).unwrap();
            });
        }
        self.io.register(move |p: Packet| {
            let data = p.data();
            let ip_version = data[0] >> 4;
            let layer_type = if ip_version == 4 {
                LayerType::IPv4
            } else if ip_version == 6 {
                LayerType::IPv6
            } else {
                self.io.set_verdict(p, Verdict::AcceptStream, None).unwrap();
                return true;
            };
            let packet = Packet::new(
                data,
                layer_type,
                DecodeOptions {
                    lazy: true,
                    no_copy: true,
                },
            );
            packet.set_metadata(Some(PacketMetadata {
                timestamp: SystemTime::now(),
            }));
            let index = (p.stream_id() % self.workers.len() as u32) as usize;
            self.workers[index].feed(WorkerPacket {
                stream_id: p.stream_id(),
                packet,
                set_verdict: Box::new(move |v: Verdict, b: Option<Vec<u8>>| {
                    self.io.set_verdict(p, v, b)
                }),
            });
            true
        })?;
        match rx.recv() {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(err),
            Err(_) => Err("Engine run error".into()),
        }
    }
}
