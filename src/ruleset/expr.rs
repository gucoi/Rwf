use crate::AnalyzerInterface;
use crate::RulesetInterface;

use serde::Deserialize;
use serde_yaml;
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize)]
pub struct ExprRule {
    name: String,
    action: String,
    modifier: ModifierEntry,
    expr: String,
}

#[derive(Deserialize)]
struct ExprRules(Vec<ExprRule>);

#[derive(Deserialize)]
pub struct ModifierEntry {
    name: String,
}

pub fn expr_rules_from_yaml(file: &str) -> Result<ExprRules, Box<dyn std::error::Error>> {
    let yaml_str = fs::read_to_string(file)?;
    let expr_rules = serde_yaml::from_str(&yaml_str)?;

    Ok(expr_rules)
}

pub struct CompiledExprRule {
    name: String,
    action: RulesetInterface::Action,
}

pub struct ExprRuleset {
    rules: Vec<CompiledExprRule>,
    ans: Vec<Box<dyn AnalyzerInterface::Analyzer>>,
}

impl CompiledExprRule {
    pub fn analyzers(info: RulesetInterface::StreamInfo) {}
}

impl ExprRuleset {
    fn analyzers(&self) -> Vec<Box<dyn AnalyzerInterface::Analyzer>> {
        self.ans
    }

    fn expr_rule_set_match(&self, info: RulesetInterface::StreamInfo) {}
}

impl<'a> RulesetInterface::StreamInfo<'a> {
    fn stream_info_to_expr_env(&self) -> Result<serde_json::Value, serde_json::Error> {
        let info_map = serde_json::json!({
            "id": self.id,
            "proto": self.protocol,
            "ip": {
                "src": self.src_ip,
                "dst": self.dst_ip
            },
            "port": {
                "src": self.src_port,
                "dst": self.dst_port
            },
            "props": self.props.iter()
                .filter(|(_, props)| !props.is_null())
                .fold(HashMap::new(), |mut acc, (name, props)| {
                    acc.insert(name.clone(), props.to_owned());
                    acc
                })
        });

        serde_json::to_value(info_map).map_err(Into::into)
    }
}
