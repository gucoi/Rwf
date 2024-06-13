use async_trait::async_trait;
use env_logger::Logger;
use evalexpr::{Context, Node};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml::from_str;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::sync::Arc;

use crate::ruleset::interface::{Action, MatchResult, Modifier, Ruleset};
use crate::AnalyzerInterface::Analyzer;
use crate::AnalyzerInterface::PropMap;

use super::interface::ModifierInstance;
use super::interface::StreamInfo;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ExprRule {
    pub name: String,
    pub action: Option<String>,
    pub log: bool,
    pub modifier: Option<ModifierEntry>,
    pub expr: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ModifierEntry {
    pub name: String,
    pub args: HashMap<String, Value>,
}

struct ExprRuleset {
    rules: Vec<CompiledExprRule>,
    ans: Vec<Box<dyn Analyzer>>,
    logger: Logger,
}

pub fn expr_rules_from_yaml(file: &str) -> Result<Vec<ExprRule>, Box<dyn Error>> {
    let content = fs::read_to_string(file)?;
    let rules: Vec<ExprRule> = from_str(&content)?;
    Ok(rules)
}

pub struct CompiledExprRule {
    pub name: String,
    pub action: Option<Action>,
    pub log: bool,
    pub mod_instance: Box<dyn ModifierInstance>,
    pub program: Node,
}

#[async_trait]
impl<'a> Ruleset<'a> for ExprRuleset {
    async fn match_rule(&self, info: &'a StreamInfo) -> MatchResult {
        let json_env = stream_info_to_expr_env(info).unwrap();
        let mut env = HashMap::new();
        for (key, value) in json_env.as_object().unwrap() {
            env.insert(key.clone(), Value::from(value.clone()));
        }
        let context = Context::from(env);

        for rule in &self.rules {
            let result = rule.program.eval_with_context(&context).unwrap();
            if let Value::Bool(v) = result {
                if v {
                    if rule.log {
                        self.logger.log(&info, &rule.name);
                    }
                    if let Some(action) = &rule.action {
                        return MatchResult {
                            action: action.clone(),
                            mod_instance: rule.mod_instance.clone(),
                        };
                    }
                }
            }
        }
        MatchResult {
            action: Action::Maybe,
            mod_instance: None,
        }
    }

    fn analyzers(&self, stream_info: &StreamInfo) -> &[Box<dyn Analyzer>] {
        &self.ans
    }
}

pub fn compile_expr_rules(
    rules: Vec<ExprRule>,
    ans: Vec<Box<dyn Analyzer>>,
    mods: Vec<Box<dyn Modifier>>,
    config: Arc<BuiltinConfig>,
) -> Result<Box<dyn Ruleset>, Box<dyn Error>> {
    let mut compiled_rules = Vec::new();
    let full_an_map = analyzers_to_map(&ans);
    let full_mod_map = modifiers_to_map(&mods);
    let mut dep_an_map = HashMap::new();
    let func_map = build_function_map(&config);
    for rule in rules {
        if rule.action.is_none() && !rule.log {
            return Err(
                format!("rule {} must have at least one of action or log", rule.name).into(),
            );
        }
        let mut action = None;
        if let Some(action_str) = rule.action {
            match action_str.as_str() {
                "maybe" => action = Some(Action::Maybe),
                "allow" => action = Some(Action::Allow),
                "block" => action = Some(Action::Block),
                "drop" => action = Some(Action::Drop),
                "modify" => action = Some(Action::Modify),
                _ => {
                    return Err(
                        format!("rule {} has invalid action {}", rule.name, action_str).into(),
                    )
                }
            }
        }
        let visitor = IdVisitor::new();
        let patcher = IdPatcher::new(&func_map);
        let program = expr::compile(&rule.expr, &mut |c| {
            c.strict = false;
            c.expect = bool::default();
            c.visitors = vec![visitor, patcher];
            for (name, f) in &func_map {
                c.functions.insert(name.clone(), f.clone());
            }
        })?;
        for name in &visitor.identifiers {
            if is_built_in_analyzer(name) || visitor.variables.contains(name) {
                continue;
            }
            if let Some(f) = func_map.get(name) {
                if let Some(init_func) = f.init_func {
                    init_func()?;
                }
            } else if let Some(a) = full_an_map.get(name) {
                dep_an_map.insert(name.clone(), a.clone());
            }
        }
        let mut cr = CompiledExprRule {
            name: rule.name.clone(),
            action,
            log: rule.log,
            program,
            mod_instance: None,
        };
        if let Some(action) = action {
            if action == Action::Modify {
                if let Some(mod_name) = &rule.modifier {
                    let modifier = full_mod_map.get(mod_name).ok_or_else(|| {
                        format!("rule {} uses unknown modifier {}", rule.name, mod_name)
                    })?;
                    let mod_instance = modifier.new_instance(&rule.modifier_args)?;
                    cr.mod_instance = Some(mod_instance);
                }
            }
        }
        compiled_rules.push(cr);
    }
    let mut dep_ans = Vec::new();
    for a in dep_an_map.values() {
        dep_ans.push(a.clone());
    }
    Ok(Box::new(ExprRuleset {
        rules: compiled_rules,
        ans: dep_ans,
        logger: config.logger.clone(),
    }))
}

fn stream_info_to_expr_env(info: &StreamInfo) -> PropMap {
    let mut m = HashMap::new();
    m.insert("id".to_string(), Value::String(info.id.clone()));
    m.insert(
        "proto".to_string(),
        Value::String(info.protocol.to_string()),
    );
    m.insert(
        "ip".to_string(),
        Value::Object(hash_map! {
            "src".to_string() => Value::String(info.src_ip.to_string()),
            "dst".to_string() => Value::String(info.dst_ip.to_string()),
        }),
    );
    m.insert(
        "port".to_string(),
        Value::Object(hash_map! {
            "src".to_string() => Value::Integer(info.src_port.into()),
            "dst".to_string() => Value::Integer(info.dst_port.into()),
        }),
    );
    for (an_name, an_props) in &info.props {
        if !an_props.is_empty() {
            m.insert(an_name.clone(), Value::Array(an_props.clone()));
        }
    }
    m
}

fn is_built_in_analyzer(name: &str) -> bool {
    matches!(name, "id" | "proto" | "ip" | "port")
}

fn action_string_to_action(action: &str) -> Option<Action> {
    match action.to_lowercase().as_str() {
        "allow" => Some(Action::Allow),
        "block" => Some(Action::Block),
        "drop" => Some(Action::Drop),
        "modify" => Some(Action::Modify),
        _ => None,
    }
}

fn analyzers_to_map(ans: &[Box<dyn Analyzer>]) -> HashMap<String, Box<dyn Analyzer>> {
    let mut an_map = HashMap::new();
    for a in ans {
        an_map.insert(a.name(), a.clone());
    }
    an_map
}

fn modifiers_to_map(mods: &[Box<dyn Modifier>]) -> HashMap<String, Box<dyn Modifier>> {
    let mut mod_map = HashMap::new();
    for m in mods {
        mod_map.insert(m.name(), m.clone());
    }
    mod_map
}
