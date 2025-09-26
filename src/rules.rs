use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
};

use glob::glob;
use serde::Deserialize;

use crate::model::{Action, RuleId, Target};

fn default_enabled() -> bool {
    true
}

/// Inline test case embedded in a rule definition.
///
/// Validated during `--check-config`; ignored at runtime.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleTest {
    /// Text fed to the regex.
    pub input: String,
    /// Target label under test (e.g. `path`, `query_string`).
    pub target: String,
    /// `"match"` or `"no_match"`.
    pub expect: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Which request/response segments this rule's regex runs against.
    pub when: Vec<Target>,
    pub r#match: String,
    /// Consequence of a match.
    pub action: Action,
    /// Intra-tier ordering.  Higher wins.  Irrelevant across tiers:
    /// `drop` dominates `forward` regardless of this value.
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub score: i32,
    /// Self-test cases for the rule's regex.  Run by `--check-config`.
    /// Non-empty failures are fatal.
    #[serde(default, rename = "test")]
    pub tests: Vec<RuleTest>,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct Bundle {
    pub rules: Vec<Rule>,
    pub sources: Vec<PathBuf>,
}

/// Errors from rule bundle loading.
///
/// Typed via thiserror so callers can match on specific failure modes.
/// The binary crate converts these to anyhow at the entry point.
#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("rules entrypoint is required")]
    EntrypointRequired,

    #[error("include depth exceeded at {path}")]
    DepthExceeded { path: PathBuf },

    #[error("cannot resolve rules path {path}: {source}")]
    ResolvePath { path: PathBuf, source: io::Error },

    #[error("cannot read rules file {path}: {source}")]
    ReadFile { path: PathBuf, source: io::Error },

    #[error("cannot decode rules file {path}: {source}")]
    DecodeFile {
        path: PathBuf,
        source: toml::de::Error,
    },

    #[error("rule in {file} is missing id")]
    ZeroId { file: PathBuf },

    #[error("rule {id} in {file} has invalid score {score} (must be >= 0)")]
    InvalidScore { id: RuleId, file: PathBuf, score: i32 },

    #[error("include '{include}' from {file} matched no files")]
    IncludeNoFiles { include: String, file: PathBuf },

    #[error("include path {path} not found")]
    IncludeNotFound { path: PathBuf },

    #[error("cannot expand include pattern '{pattern}': {source}")]
    GlobPattern {
        pattern: String,
        source: glob::PatternError,
    },

    #[error("cannot read glob match for pattern '{pattern}': {source}")]
    GlobMatch {
        pattern: String,
        source: glob::GlobError,
    },

    #[error("cannot read include directory {path}: {source}")]
    ReadDirectory { path: PathBuf, source: io::Error },

    #[error("cannot read entry in {path}: {source}")]
    ReadDirEntry { path: PathBuf, source: io::Error },

    #[error("duplicate rule id {id} in {file} (first defined in {previous_file})")]
    DuplicateId {
        id: RuleId,
        file: PathBuf,
        previous_file: PathBuf,
    },
}

pub fn load_bundle(
    entrypoint: impl AsRef<Path>,
    max_depth: usize,
) -> Result<Bundle, RuleLoadError> {
    let entrypoint = entrypoint.as_ref();
    if entrypoint.as_os_str().is_empty() {
        return Err(RuleLoadError::EntrypointRequired);
    }

    let max_depth = if max_depth == 0 { 16 } else { max_depth };
    let mut visited = HashSet::new();
    let mut seen_ids = HashMap::new();
    let mut bundle = Bundle {
        rules: Vec::new(),
        sources: Vec::new(),
    };

    load_file(
        entrypoint,
        0,
        max_depth,
        &mut visited,
        &mut seen_ids,
        &mut bundle,
    )?;
    bundle.sources.sort();
    Ok(bundle)
}

fn load_file(
    path: &Path,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<PathBuf>,
    seen_ids: &mut HashMap<RuleId, PathBuf>,
    bundle: &mut Bundle,
) -> Result<(), RuleLoadError> {
    if depth > max_depth {
        return Err(RuleLoadError::DepthExceeded {
            path: path.to_owned(),
        });
    }

    let resolved = path
        .canonicalize()
        .map_err(|source| RuleLoadError::ResolvePath {
            path: path.to_owned(),
            source,
        })?;
    if !visited.insert(resolved.clone()) {
        return Ok(());
    }

    let contents =
        fs::read_to_string(&resolved).map_err(|source| RuleLoadError::ReadFile {
            path: resolved.clone(),
            source,
        })?;
    let data: RuleFile =
        toml::from_str(&contents).map_err(|source| RuleLoadError::DecodeFile {
            path: resolved.clone(),
            source,
        })?;

    bundle.sources.push(resolved.clone());
    for rule in data.rules {
        if rule.id.is_zero() {
            return Err(RuleLoadError::ZeroId {
                file: resolved.clone(),
            });
        }
        if !rule.enabled {
            continue;
        }
        if rule.score < 0 {
            return Err(RuleLoadError::InvalidScore {
                id: rule.id,
                file: resolved.clone(),
                score: rule.score,
            });
        }
        if let Some(previous_file) = seen_ids.get(&rule.id) {
            return Err(RuleLoadError::DuplicateId {
                id: rule.id,
                file: resolved.clone(),
                previous_file: previous_file.clone(),
            });
        }
        seen_ids.insert(rule.id, resolved.clone());
        bundle.rules.push(rule);
    }

    let base_dir = resolved.parent().unwrap_or(Path::new("."));
    for include in data.include {
        let targets = resolve_include_targets(base_dir, &include)?;

        if targets.is_empty() {
            return Err(RuleLoadError::IncludeNoFiles {
                include: include.clone(),
                file: resolved.clone(),
            });
        }

        for matched in targets {
            load_file(&matched, depth + 1, max_depth, visited, seen_ids, bundle)?;
        }
    }

    Ok(())
}

fn resolve_include_targets(
    base_dir: &Path,
    include: &str,
) -> Result<Vec<PathBuf>, RuleLoadError> {
    let include_path = if Path::new(include).is_absolute() {
        PathBuf::from(include)
    } else {
        base_dir.join(include)
    };

    if has_glob_meta(include) {
        let pattern = include_path.to_string_lossy().into_owned();
        let mut matches = Vec::new();
        for entry in glob(&pattern).map_err(|source| RuleLoadError::GlobPattern {
            pattern: pattern.clone(),
            source,
        })? {
            let matched = entry.map_err(|source| RuleLoadError::GlobMatch {
                pattern: pattern.clone(),
                source,
            })?;
            if matched.is_file() {
                matches.push(matched);
            }
        }
        matches.sort();
        return Ok(matches);
    }

    if include_path.is_dir() {
        let mut entries = Vec::new();
        for entry in
            fs::read_dir(&include_path).map_err(|source| RuleLoadError::ReadDirectory {
                path: include_path.clone(),
                source,
            })?
        {
            let path = entry
                .map_err(|source| RuleLoadError::ReadDirEntry {
                    path: include_path.clone(),
                    source,
                })?
                .path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
                entries.push(path);
            }
        }
        entries.sort();
        return Ok(entries);
    }

    if include_path.is_file() {
        return Ok(vec![include_path]);
    }

    Err(RuleLoadError::IncludeNotFound { path: include_path })
}

fn has_glob_meta(input: &str) -> bool {
    input.contains('*') || input.contains('?') || input.contains('[')
}

/// Result of a single inline rule test case.
#[derive(Debug)]
pub struct TestResult {
    pub rule_id: RuleId,
    pub test_idx: usize,
    pub input: String,
    pub target: String,
    pub expected_match: bool,
    pub actual_match: bool,
    pub passed: bool,
}

/// Run every `[[rule.test]]` block in the bundle.
///
/// Returns one `TestResult` per test.  A result with `passed == false`
/// is a failing assertion; the caller decides whether to abort.
pub fn run_bundle_tests(bundle: &Bundle) -> anyhow::Result<Vec<TestResult>> {
    use anyhow::Context as _;

    let mut results = Vec::new();
    for rule in &bundle.rules {
        if rule.tests.is_empty() {
            continue;
        }
        let regex = regex::RegexBuilder::new(&rule.r#match)
            .size_limit(10 * 1024 * 1024)
            .build()
            .with_context(|| format!("rule {}: invalid regex '{}'", rule.id, rule.r#match))?;
        for (idx, test) in rule.tests.iter().enumerate() {
            let actual = regex.is_match(&test.input);
            let expected = test.expect.trim().to_ascii_lowercase() == "match";
            results.push(TestResult {
                rule_id: rule.id,
                test_idx: idx,
                input: test.input.clone(),
                target: test.target.clone(),
                expected_match: expected,
                actual_match: actual,
                passed: actual == expected,
            });
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_rules(temp: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = temp.path().join(name);
        fs::write(&path, content).expect("write rules file");
        path
    }

    #[test]
    fn minimal_rule_loads() {
        let temp = TempDir::new().unwrap();
        let path = write_rules(
            &temp,
            "rules.toml",
            r#"
[[rule]]
id     = 42
when   = ["path"]
match  = "^/test"
action = "log"
"#,
        );
        let bundle = load_bundle(&path, 8).unwrap();
        assert_eq!(bundle.rules.len(), 1);
        let rule = &bundle.rules[0];
        assert_eq!(rule.id, RuleId(42));
        assert!(rule.name.is_none());
        assert!(rule.description.is_none());
        assert!(rule.tags.is_empty());
        assert!(rule.enabled);
        assert_eq!(rule.priority, 0);
        assert_eq!(rule.score, 0);
    }

    #[test]
    fn full_rule_fields_load() {
        let temp = TempDir::new().unwrap();
        let path = write_rules(
            &temp,
            "rules.toml",
            r#"
[[rule]]
id          = 200
name        = "sql_probe"
description = "SQL injection probe."
tags        = ["sqli", "owasp-a03"]
enabled     = true
when        = ["query_string", "body"]
match       = "(?i)union"
action      = "reject"
priority    = 100
score       = 10
"#,
        );
        let bundle = load_bundle(&path, 8).unwrap();
        let rule = &bundle.rules[0];
        assert_eq!(rule.name.as_deref(), Some("sql_probe"));
        assert_eq!(rule.description.as_deref(), Some("SQL injection probe."));
        assert_eq!(rule.tags, ["sqli", "owasp-a03"]);
        assert_eq!(rule.priority, 100);
        assert_eq!(rule.score, 10);
    }

    #[test]
    fn disabled_rule_is_skipped_at_load() {
        let temp = TempDir::new().unwrap();
        let path = write_rules(
            &temp,
            "rules.toml",
            r#"
[[rule]]
id      = 1
when    = ["path"]
match   = "^/a"
action  = "log"
enabled = false

[[rule]]
id     = 2
when   = ["path"]
match  = "^/b"
action = "log"
"#,
        );
        let bundle = load_bundle(&path, 8).unwrap();
        assert_eq!(bundle.rules.len(), 1);
        assert_eq!(bundle.rules[0].id, RuleId(2));
    }

    #[test]
    fn negative_score_rejected() {
        let temp = TempDir::new().unwrap();
        let path = write_rules(
            &temp,
            "rules.toml",
            r#"
[[rule]]
id     = 1
when   = ["path"]
match  = "^/a"
action = "log"
score  = -1
"#,
        );
        let err = load_bundle(&path, 8).unwrap_err();
        assert!(
            err.to_string().contains("invalid score"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let temp = TempDir::new().unwrap();
        let path = write_rules(
            &temp,
            "rules.toml",
            r#"
[[rule]]
id     = 100
name   = "first"
when   = ["path"]
match  = "^/first"
action = "log"

[[rule]]
id     = 100
name   = "second"
when   = ["path"]
match  = "^/second"
action = "reject"
"#,
        );
        let err = load_bundle(&path, 8).unwrap_err();
        assert!(
            err.to_string().contains("duplicate rule id 100"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn zero_id_is_rejected() {
        let temp = TempDir::new().unwrap();
        let path = write_rules(
            &temp,
            "rules.toml",
            r#"
[[rule]]
id     = 0
when   = ["path"]
match  = "^/a"
action = "log"
"#,
        );
        let err = load_bundle(&path, 8).unwrap_err();
        assert!(
            err.to_string().contains("missing id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn directory_include_loads_sorted() {
        let temp = TempDir::new().unwrap();
        let sub = temp.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(
            sub.join("02-b.toml"),
            "[[rule]]\nid=2\nwhen=[\"path\"]\nmatch=\"^/b\"\naction=\"log\"\n",
        )
        .unwrap();
        fs::write(
            sub.join("01-a.toml"),
            "[[rule]]\nid=1\nwhen=[\"path\"]\nmatch=\"^/a\"\naction=\"log\"\n",
        )
        .unwrap();
        let entrypoint = write_rules(&temp, "main.toml", "include = [\"sub\"]\n");
        let bundle = load_bundle(&entrypoint, 8).unwrap();
        // Lexical order: 01-a before 02-b
        assert_eq!(bundle.rules[0].id, RuleId(1));
        assert_eq!(bundle.rules[1].id, RuleId(2));
    }
}


