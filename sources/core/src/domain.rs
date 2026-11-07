use std::{collections::BTreeSet, fmt, net::IpAddr, num::NonZeroUsize, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A validated, lowercase ASCII hostname without a trailing root dot.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainName(String);

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error(
    "expected a DNS hostname with valid labels; URLs, IP addresses and wildcard labels are not hostnames"
)]
pub struct DomainError;

impl DomainName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn relative_to<'a>(&'a self, parent: &Self) -> Option<&'a str> {
        self.0.strip_suffix(&parent.0)?.strip_suffix('.')
    }
}

impl FromStr for DomainName {
    type Err = DomainError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // IDNA's strict mode also rejects interior hyphen combinations used by ordinary CDN
        // hostnames. Apply IDNA conversion, then validate the DNS hostname's LDH labels here.
        let input = input.strip_suffix('.').unwrap_or(input);
        if input.is_empty() || input.chars().any(char::is_whitespace) {
            return Err(DomainError);
        }
        let ascii = idna::domain_to_ascii(input)
            .map_err(|_| DomainError)?
            .to_ascii_lowercase();
        if ascii.len() > 253 || ascii.parse::<IpAddr>().is_ok() {
            return Err(DomainError);
        }
        for label in ascii.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(DomainError);
            }
        }
        Ok(Self(ascii))
    }
}

impl TryFrom<String> for DomainName {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<DomainName> for String {
    fn from(value: DomainName) -> Self {
        value.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Project match modes: exact, `*.`, `**.`, and `***.` respectively.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchScope {
    Exact,
    DirectSubdomains,
    AllSubdomains,
    DomainAndSubdomains,
}

/// The base name is always a hostname; scope carries wildcard semantics separately.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainPattern {
    pub domain: DomainName,
    pub scope: MatchScope,
}

impl DomainPattern {
    pub fn matches(&self, candidate: &DomainName) -> bool {
        let relative = candidate.relative_to(&self.domain);
        match self.scope {
            MatchScope::Exact => candidate == &self.domain,
            MatchScope::DirectSubdomains => relative.is_some_and(|prefix| !prefix.contains('.')),
            MatchScope::AllSubdomains => relative.is_some(),
            MatchScope::DomainAndSubdomains => candidate == &self.domain || relative.is_some(),
        }
    }
}

impl FromStr for DomainPattern {
    type Err = DomainError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (base, scope) = if let Some(base) = input.strip_prefix("***.") {
            (base, MatchScope::DomainAndSubdomains)
        } else if let Some(base) = input.strip_prefix("**.") {
            (base, MatchScope::AllSubdomains)
        } else if let Some(base) = input.strip_prefix("*.") {
            (base, MatchScope::DirectSubdomains)
        } else {
            (input, MatchScope::Exact)
        };
        Ok(Self {
            domain: base.parse()?,
            scope,
        })
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.scope {
            MatchScope::Exact => "",
            MatchScope::DirectSubdomains => "*.",
            MatchScope::AllSubdomains => "**.",
            MatchScope::DomainAndSubdomains => "***.",
        };
        formatter.write_str(prefix)?;
        self.domain.fmt(formatter)
    }
}

impl TryFrom<String> for DomainPattern {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<DomainPattern> for String {
    fn from(value: DomainPattern) -> Self {
        value.to_string()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub pattern: DomainPattern,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuleSetError {
    #[error("invalid domain pattern on line {line}")]
    InvalidLine {
        line: usize,
        #[source]
        source: DomainError,
    },
    #[error("the exception list exceeds its configured capacity")]
    Capacity,
    #[error("the exception list contains a duplicate domain and match mode")]
    Duplicate,
}

impl RuleSet {
    /// Parse one enabled exception per nonblank line. Validation is all-or-nothing.
    pub fn from_lines(input: &str, capacity: NonZeroUsize) -> Result<Self, RuleSetError> {
        let mut rules = Vec::new();
        for (index, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if rules.len() >= capacity.get() {
                return Err(RuleSetError::Capacity);
            }
            let number = index.checked_add(1).ok_or(RuleSetError::Capacity)?;
            let pattern = line.parse().map_err(|source| RuleSetError::InvalidLine {
                line: number,
                source,
            })?;
            rules.push(Rule {
                pattern,
                enabled: true,
            });
        }
        Self::new(rules, capacity)
    }

    pub fn new(rules: Vec<Rule>, capacity: NonZeroUsize) -> Result<Self, RuleSetError> {
        if rules.len() > capacity.get() {
            return Err(RuleSetError::Capacity);
        }
        let mut patterns = BTreeSet::new();
        for rule in &rules {
            if !patterns.insert(&rule.pattern) {
                return Err(RuleSetError::Duplicate);
            }
        }
        Ok(Self { rules })
    }

    /// Disabled entries do not negate other enabled rules, including enabled parent domains.
    pub fn selects(&self, name: &DomainName) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.enabled && rule.pattern.matches(name))
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}
