use crate::RulesetInterface;
use clap::Parser;
use config::{Config, File};
use log::{debug, error, info};
use std::{error, fmt};

#[derive(Debug)]
pub struct ConfigError {
    field: String,
    err: Box<dyn error::Error>,
}

impl ConfigError {
    fn new(field: String, err: Box<dyn error::Error>) -> Self {
        ConfigError { field, err }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid config: {}: {}", self.field, self.err)
    }
}

pub struct Cmd {}

impl Cmd {
    pub fn new() -> Self {
        Cmd {}
    }

    pub fn execute(&self) {
        self.init();
    }

    fn init(&self) {
        let args = Arg::parse();
        if let Err(err) = self.init_config_from_file(&args.config_file) {
            error!("{}", err);
        } else {
            info!("Config initialized successfully");
        }
    }

    fn init_config_from_file(&self, cfg_file: &str) -> Result<Config, ConfigError> {
        let mut settings = Config::default();
        settings.merge(File::with_name(cfg_file)).map_err(|err| {
            ConfigError::new("Failed to parse config file".to_string(), Box::new(err))
        })?;
        Ok(settings)
    }
}

#[derive(Parser)]
pub struct Arg {
    #[arg(short, long)]
    config_file: String,
}

struct EngineLogger;

impl EngineLogger {
    fn udp_stream_action(
        &self,
        info: RulesetInterface::StreamInfo,
        action: RulesetInterface::Action,
        no_match: bool,
    ) {
        info!(
            "UDP stream action - id: {}, src: {}, dst: {}, action: {}, noMatch: {}",
            info.id,
            info.src_string(),
            info.dst_string(),
            action.to_string(),
            no_match
        );
    }

    fn match_error(&self, info: RulesetInterface::StreamInfo, err: Box<dyn error::Error>) {
        error!(
            "match error - id: {}, src: {}, dst: {}, error: {}",
            info.id,
            info.src_string(),
            info.dst_string(),
            err
        );
    }

    fn modify_error(&self, info: RulesetInterface::StreamInfo, err: Box<dyn error::Error>) {
        error!(
            "modify error - id: {}, src: {}, dst: {}, error: {}",
            info.id,
            info.src_string(),
            info.dst_string(),
            err
        );
    }

    fn analyzer_debugf(
        &self,
        stream_id: i64,
        name: &str,
        format: &str,
        _args: &[&dyn std::fmt::Debug],
    ) {
        debug!(
            "analyzer debug message - id: {}, name: {}, msg: {}",
            stream_id, name, format
        );
    }
}
