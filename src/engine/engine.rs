use crate::{
    engine::interface::{Config, Logger},
    IOInterface::PakcetIO,
};
use num_cpus;

struct Engine {
    logger: Box<dyn Logger>,
    io_list: Vec<Box<dyn PakcetIO>>,
}

impl Engine {
    pub fn new(config: Config) -> Self {
        let mut worker_count = config.get_workers();
        if worker_count <= 0 {
            worker_count = num_cpus::get() as i32;
        }
    }
}
