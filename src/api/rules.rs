//! Stable rule-scan records for front ends.

use crate::workspace::Session;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatchSummary {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
    pub patterns: Vec<(String, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleScanSummary {
    pub source: String,
    pub source_files: usize,
    pub matches: Vec<RuleMatchSummary>,
}

impl RuleScanSummary {
    pub fn rule_names(&self) -> Vec<String> {
        self.matches
            .iter()
            .map(|matched| matched.rule.clone())
            .collect()
    }
}

pub fn scan_path(session: &Session, path: &str) -> Result<RuleScanSummary> {
    let (compiled, source_files) = crate::analysis::yara::compile(path)?;
    let matches = crate::analysis::yara::scan(&compiled, &session.bytes)?
        .into_iter()
        .map(|matched| RuleMatchSummary {
            rule: matched.rule,
            namespace: matched.namespace,
            tags: matched.tags,
            meta: matched.meta,
            patterns: matched.patterns,
        })
        .collect();
    Ok(RuleScanSummary {
        source: path.to_string(),
        source_files,
        matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_path_returns_stable_rule_records() {
        let root = std::env::temp_dir().join(format!(
            "knife-rule-api-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("fixture.exe");
        let database = root.join("fixture.json");
        let rule = root.join("pe.yar");
        std::fs::write(&target, crate::formats::fixture::pe_with_iat_call()).unwrap();
        std::fs::write(
            &rule,
            r#"rule PeHeader { meta: source = "test" condition: uint16(0) == 0x5a4d }"#,
        )
        .unwrap();
        let session = Session::open(
            target.to_str().unwrap(),
            database.to_str(),
            200_000,
            "rule facade test",
        )
        .unwrap();

        let scan = scan_path(&session, rule.to_str().unwrap()).unwrap();
        assert_eq!(scan.source_files, 1);
        assert_eq!(scan.rule_names(), vec!["PeHeader"]);
        assert_eq!(scan.matches[0].namespace, "default");
        assert!(scan.matches[0]
            .meta
            .iter()
            .any(|(key, value)| key == "source" && value == "test"));
        let _ = std::fs::remove_dir_all(root);
    }
}
