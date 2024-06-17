use std::sync::Mutex;

use crate::RulesetInterface::Ruleset;

pub struct TcoStreamFactory {
    worker_id: i32,
    ruleset_mutex: Mutex<Box<dyn Ruleset>>,
    ruleset: dyn Ruleset,
}
