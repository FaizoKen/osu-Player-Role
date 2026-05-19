//! Parse and validate the rule-tree payload sent by the iframe UI on save.
//! Returns a clean [`RuleTree`] ready to persist as `role_links.rule_tree`
//! JSONB.

use serde::Deserialize;
use serde_json::Value;

use crate::error::AppError;
use crate::models::condition::{Condition, ConditionOperator, ConditionTarget, TargetKind};
use crate::models::mode::Mode;
use crate::models::rule::{ConditionGroup, RuleTree, MAX_CONDITIONS_PER_GROUP, MAX_GROUPS};

#[derive(Debug, Deserialize)]
pub struct RuleTreeBody {
    #[serde(default)]
    pub grant_on_any_player: bool,
    /// Game mode the per-mode conditions evaluate against. Accepts the
    /// canonical names ("osu", "taiko", "fruits", "mania") and a couple of
    /// historical aliases ("standard", "ctb", "catch").
    #[serde(default)]
    pub default_mode: Option<String>,
    #[serde(default)]
    pub groups: Vec<ConditionGroupInput>,
}

#[derive(Debug, Deserialize)]
pub struct ConditionGroupInput {
    #[serde(default)]
    pub conditions: Vec<ConditionInput>,
}

#[derive(Debug, Deserialize)]
pub struct ConditionInput {
    pub target: String,
    pub operator: String,
    #[serde(default)]
    pub value: Value,
    #[serde(default)]
    pub value_end: Option<Value>,
}

pub struct ParsedRule {
    pub rule_tree: RuleTree,
}

pub fn parse_rule_tree(body: RuleTreeBody) -> Result<ParsedRule, AppError> {
    let default_mode = match body.default_mode.as_deref().map(str::trim) {
        None | Some("") => Mode::default(),
        Some(s) => Mode::from_key(s).ok_or_else(|| {
            AppError::BadRequest(format!(
                "Unknown game mode '{s}'. Pick osu, taiko, fruits, or mania."
            ))
        })?,
    };

    if !body.grant_on_any_player {
        if body.groups.is_empty() {
            return Err(AppError::BadRequest(
                "Add at least one OR-group, or pick \"any linked osu! player\".".into(),
            ));
        }
        if body.groups.len() > MAX_GROUPS {
            return Err(AppError::BadRequest(format!(
                "At most {MAX_GROUPS} OR-groups per role."
            )));
        }
    }

    let mut groups: Vec<ConditionGroup> = Vec::with_capacity(body.groups.len());
    if !body.grant_on_any_player {
        for (gi, raw_group) in body.groups.into_iter().enumerate() {
            let group_num = gi + 1;
            if raw_group.conditions.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "Group #{group_num}: add at least one condition (or remove the group)."
                )));
            }
            if raw_group.conditions.len() > MAX_CONDITIONS_PER_GROUP {
                return Err(AppError::BadRequest(format!(
                    "Group #{group_num}: at most {MAX_CONDITIONS_PER_GROUP} conditions per group."
                )));
            }
            let mut conditions: Vec<Condition> = Vec::with_capacity(raw_group.conditions.len());
            for (ci, raw) in raw_group.conditions.into_iter().enumerate() {
                conditions.push(validate_condition(group_num, ci + 1, raw)?);
            }
            groups.push(ConditionGroup { conditions });
        }
    }

    Ok(ParsedRule {
        rule_tree: RuleTree {
            grant_on_any_player: body.grant_on_any_player,
            default_mode,
            groups,
        },
    })
}

fn validate_condition(
    group_num: usize,
    cond_num: usize,
    raw: ConditionInput,
) -> Result<Condition, AppError> {
    let where_ = format!("Group #{group_num}, condition #{cond_num}");

    let target = ConditionTarget::from_key(raw.target.trim()).ok_or_else(|| {
        AppError::BadRequest(format!("{where_}: unknown target '{}'.", raw.target))
    })?;

    let operator = ConditionOperator::from_key(raw.operator.trim()).ok_or_else(|| {
        AppError::BadRequest(format!("{where_}: unknown operator '{}'.", raw.operator))
    })?;

    if !operator.valid_for(target.kind()) {
        return Err(AppError::BadRequest(format!(
            "{where_}: operator '{}' is not valid for '{}'.",
            operator.as_str(),
            target.as_str()
        )));
    }

    let value = normalize_value(&where_, target.kind(), operator, raw.value)?;
    let value_end = match (operator, raw.value_end) {
        (ConditionOperator::Between, Some(end)) => {
            Some(normalize_value(&where_, target.kind(), operator, end)?)
        }
        (ConditionOperator::Between, None) => {
            return Err(AppError::BadRequest(format!(
                "{where_}: \"between\" needs both a min and a max value."
            )));
        }
        _ => None,
    };

    // Compile regex at save time so a bad pattern can't surface only at eval.
    if matches!(operator, ConditionOperator::Regex) {
        let pattern = value.as_str().unwrap_or("");
        if regex::RegexBuilder::new(pattern)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .is_err()
        {
            return Err(AppError::BadRequest(format!(
                "{where_}: regex pattern is invalid."
            )));
        }
    }

    Ok(Condition {
        target,
        operator,
        value,
        value_end,
    })
}

fn normalize_value(
    where_: &str,
    kind: TargetKind,
    op: ConditionOperator,
    raw: Value,
) -> Result<Value, AppError> {
    match (kind, op) {
        (TargetKind::Bool, _) => match &raw {
            Value::Bool(_) => Ok(raw),
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(Value::Bool(true)),
                "false" | "0" | "no" => Ok(Value::Bool(false)),
                _ => Err(AppError::BadRequest(format!(
                    "{where_}: boolean value required (got {raw})."
                ))),
            },
            _ => Err(AppError::BadRequest(format!(
                "{where_}: boolean value required (got {raw})."
            ))),
        },
        (TargetKind::Int, _) => {
            let n = match &raw {
                Value::Number(num) => num.as_i64().or_else(|| num.as_f64().map(|f| f as i64)),
                Value::String(s) => s.trim().parse::<i64>().ok(),
                _ => None,
            };
            n.map(Value::from).ok_or_else(|| {
                AppError::BadRequest(format!("{where_}: integer value required (got {raw})."))
            })
        }
        (TargetKind::String, ConditionOperator::In | ConditionOperator::NotIn) => {
            let arr: Vec<Value> = match raw {
                Value::Array(a) => a
                    .into_iter()
                    .filter(|v| !matches!(v, Value::Null))
                    .filter(|v| !v.as_str().is_some_and(str::is_empty))
                    .collect(),
                Value::String(s) => s
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect(),
                Value::Null => vec![],
                other => vec![other],
            };
            if arr.is_empty() {
                return Err(AppError::BadRequest(format!(
                    "{where_}: list operator needs at least one value."
                )));
            }
            Ok(Value::Array(arr))
        }
        (TargetKind::String, _) => match raw {
            Value::String(s) => {
                if s.trim().is_empty() {
                    Err(AppError::BadRequest(format!("{where_}: value required.")))
                } else {
                    Ok(Value::String(s))
                }
            }
            Value::Number(num) => Ok(Value::String(num.to_string())),
            Value::Bool(b) => Ok(Value::String(b.to_string())),
            _ => Err(AppError::BadRequest(format!("{where_}: value required."))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(target: &str, operator: &str, value: Value) -> ConditionInput {
        ConditionInput {
            target: target.into(),
            operator: operator.into(),
            value,
            value_end: None,
        }
    }

    fn one_group(conds: Vec<ConditionInput>) -> RuleTreeBody {
        RuleTreeBody {
            grant_on_any_player: false,
            default_mode: Some("osu".into()),
            groups: vec![ConditionGroupInput { conditions: conds }],
        }
    }

    #[test]
    fn grant_on_any_no_groups_ok() {
        let body = RuleTreeBody {
            grant_on_any_player: true,
            default_mode: Some("mania".into()),
            groups: vec![],
        };
        let parsed = parse_rule_tree(body).unwrap();
        assert!(parsed.rule_tree.grant_on_any_player);
        assert_eq!(parsed.rule_tree.default_mode, Mode::Mania);
        assert!(parsed.rule_tree.groups.is_empty());
    }

    #[test]
    fn rejects_unknown_mode() {
        let body = RuleTreeBody {
            grant_on_any_player: true,
            default_mode: Some("typing-game".into()),
            groups: vec![],
        };
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn mode_aliases_accepted() {
        for alias in ["standard", "ctb", "catch"] {
            let body = RuleTreeBody {
                grant_on_any_player: true,
                default_mode: Some(alias.into()),
                groups: vec![],
            };
            assert!(parse_rule_tree(body).is_ok(), "alias {alias} should parse");
        }
    }

    #[test]
    fn convention_42_rejects_no_groups_no_grant() {
        let body = RuleTreeBody {
            grant_on_any_player: false,
            default_mode: Some("osu".into()),
            groups: vec![],
        };
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_operator_target_mismatch() {
        let body = one_group(vec![input("is_supporter", "gt", json!(0))]);
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn int_coerces_from_string() {
        let body = one_group(vec![input("global_rank", "lte", json!("1000"))]);
        let parsed = parse_rule_tree(body).unwrap();
        assert_eq!(parsed.rule_tree.groups[0].conditions[0].value, json!(1000));
    }

    #[test]
    fn country_list_normalizes_csv() {
        let body = one_group(vec![input("country_code", "in", json!("JP, KR ,US"))]);
        let parsed = parse_rule_tree(body).unwrap();
        assert_eq!(
            parsed.rule_tree.groups[0].conditions[0].value,
            json!(["JP", "KR", "US"])
        );
    }

    #[test]
    fn between_requires_value_end() {
        let body = RuleTreeBody {
            grant_on_any_player: false,
            default_mode: Some("osu".into()),
            groups: vec![ConditionGroupInput {
                conditions: vec![ConditionInput {
                    target: "performance_points".into(),
                    operator: "between".into(),
                    value: json!(5000),
                    value_end: None,
                }],
            }],
        };
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn caps_max_groups() {
        let mut groups = Vec::new();
        for _ in 0..(MAX_GROUPS + 1) {
            groups.push(ConditionGroupInput {
                conditions: vec![input("is_supporter", "eq", json!(true))],
            });
        }
        let body = RuleTreeBody {
            grant_on_any_player: false,
            default_mode: Some("osu".into()),
            groups,
        };
        assert!(matches!(
            parse_rule_tree(body),
            Err(AppError::BadRequest(_))
        ));
    }
}
