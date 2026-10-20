//! Strict sing-box JSON and SRS v1–v5 domain/IP headless rule sets.
//! Source: sing-box common/srs/{binary,ip_set}.go, option/rule_set.go and
//! route/rule/rule_abstract.go. Default address fields form OR groups;
//! source and destination groups combine with AND. Logical nodes retain
//! their nesting and invert flags instead of flattening into a domain list.

use meow_common::{Metadata, RuleMatchHelper};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::data_reader::{DataReader, MAX_BYTES, MAX_DEPTH, MAX_ITEMS, MAX_RULES};
use crate::ip_set::{IpRangeSet, IpRangeSetBuilder};
use crate::rule_set::{DomainRuleSet, DomainRuleSetBuilder, RuleSet, RuleSetBehavior};

#[derive(Default)]
struct Budget {
    nodes: usize,
    items: usize,
    regex_bytes: usize,
    regex_count: usize,
}
impl Budget {
    fn node(&mut self, depth: usize) -> Result<(), String> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_RULES {
            return Err("headless rule nesting/count limit exceeded".into());
        }
        Ok(())
    }
    fn items(&mut self, n: usize) -> Result<(), String> {
        self.items = self.items.checked_add(n).ok_or("item count overflow")?;
        if self.items > MAX_ITEMS {
            return Err("headless item count exceeds limit".into());
        }
        Ok(())
    }
    fn regex(&mut self, pattern: &str) -> Result<regex::Regex, String> {
        self.regex_bytes += pattern.len();
        self.regex_count += 1;
        if self.regex_bytes > 1024 * 1024 || self.regex_count > 128 {
            return Err("headless regex budget exceeded".into());
        }
        regex::RegexBuilder::new(pattern)
            .size_limit(256 * 1024)
            .dfa_size_limit(64 * 1024)
            .build()
            .map_err(|e| format!("invalid/oversize headless regex: {e}"))
    }
}

#[derive(Default)]
struct AddressRule {
    domains: Option<DomainRuleSet>,
    keywords: Vec<String>,
    regexes: Vec<regex::Regex>,
    source: Option<IpRangeSet>,
    destination: Option<IpRangeSet>,
}
enum NodeKind {
    Address(Box<AddressRule>),
    Logical { and: bool, rules: Vec<Node> },
}
struct Node {
    kind: NodeKind,
    invert: bool,
    axes: u8,
}
impl Node {
    fn matches(&self, host: &str, source: Option<IpAddr>, destination: Option<IpAddr>) -> bool {
        let matched = match &self.kind {
            NodeKind::Logical { and, rules } => {
                if *and {
                    rules.iter().all(|r| r.matches(host, source, destination))
                } else {
                    rules.iter().any(|r| r.matches(host, source, destination))
                }
            }
            NodeKind::Address(r) => {
                let has_destination = self.axes & 3 != 0;
                let destination_match = !has_destination
                    || (!host.is_empty()
                        && (r.domains.as_ref().is_some_and(|d| d.matches_domain(host))
                            || r.keywords.iter().any(|k| host.contains(k))
                            || r.regexes.iter().any(|re| re.is_match(host))))
                    || destination
                        .is_some_and(|ip| r.destination.as_ref().is_some_and(|s| s.contains(ip)));
                destination_match
                    && r.source
                        .as_ref()
                        .is_none_or(|s| source.is_some_and(|ip| s.contains(ip)))
            }
        };
        matched != self.invert
    }
}

struct HeadlessSet {
    behavior: RuleSetBehavior,
    nodes: Vec<Node>,
    axes: u8,
}
impl RuleSet for HeadlessSet {
    fn behavior(&self) -> RuleSetBehavior {
        self.behavior
    }
    fn len(&self) -> usize {
        self.nodes.len()
    }
    fn should_resolve_ip(&self) -> bool {
        self.axes & 2 != 0
    }
    fn matches(&self, metadata: &Metadata, _: &RuleMatchHelper) -> bool {
        self.nodes
            .iter()
            .any(|n| n.matches(&metadata.host, metadata.src_ip, metadata.dst_ip))
    }
    fn matches_domain(&self, host: &str) -> bool {
        self.nodes.iter().any(|n| n.matches(host, None, None))
    }
}

fn finish(nodes: Vec<Node>, behavior: RuleSetBehavior) -> Result<Box<dyn RuleSet>, String> {
    let axes = nodes.iter().fold(0, |a, n| a | n.axes);
    let valid = match behavior {
        RuleSetBehavior::Domain => axes & !1 == 0,
        RuleSetBehavior::IpCidr => axes & !2 == 0,
        RuleSetBehavior::Classical => true,
    };
    if !valid {
        return Err(format!("headless conditions do not fit {behavior} behavior; use classical for mixed/source-IP rules"));
    }
    Ok(Box::new(HeadlessSet {
        behavior,
        nodes,
        axes,
    }))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Strings {
    One(String),
    Many(Vec<String>),
}
impl Default for Strings {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}
impl Strings {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSet {
    version: u8,
    rules: Vec<SourceRule>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SourceRule {
    #[serde(rename = "type")]
    kind: String,
    domain: Strings,
    domain_suffix: Strings,
    domain_keyword: Strings,
    domain_regex: Strings,
    source_ip_cidr: Strings,
    ip_cidr: Strings,
    invert: bool,
    mode: Option<String>,
    rules: Option<Vec<SourceRule>>,
}

/// Read strict sing-box source JSON (versions 1–5). Unknown fields are errors.
pub fn from_json(bytes: &[u8], behavior: RuleSetBehavior) -> Result<Box<dyn RuleSet>, String> {
    json_bounds(bytes)?;
    let source: SourceSet =
        serde_json::from_slice(bytes).map_err(|e| format!("sing-box JSON: {e}"))?;
    version(source.version)?;
    if source.rules.len() > MAX_RULES {
        return Err("headless rule count exceeds limit".into());
    }
    let mut budget = Budget::default();
    let nodes = source
        .rules
        .into_iter()
        .map(|r| compile_json(r, 0, &mut budget))
        .collect::<Result<_, _>>()?;
    finish(nodes, behavior)
}

/// Distinguish sing-box source JSON from JSON-encoded Clash YAML payloads
/// without retaining an extra Value tree. Full parsing still validates it.
pub fn is_source_json(bytes: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Marker {
        version: Option<serde::de::IgnoredAny>,
        rules: Option<serde::de::IgnoredAny>,
    }
    json_bounds(bytes).is_ok()
        && serde_json::from_slice::<Marker>(bytes)
            .is_ok_and(|m| m.version.is_some() || m.rules.is_some())
}

fn version(v: u8) -> Result<(), String> {
    if !(1..=5).contains(&v) {
        return Err(format!(
            "unsupported sing-box rule-set version {v} (supported: 1–5)"
        ));
    }
    Ok(())
}

// Check allocation/depth bounds before serde constructs any owned rule tree.
// JSON syntax, string escapes, types and duplicate/unknown fields are then
// validated by serde; this scan is only an allocation budget, not a parser.
fn json_bounds(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_BYTES {
        return Err("sing-box JSON exceeds 64 MiB".into());
    }
    let (mut string, mut escape, mut depth, mut objects, mut values) =
        (false, false, 0usize, 0usize, 0usize);
    for &b in bytes {
        if string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                string = false;
            }
            continue;
        }
        match b {
            b'"' => {
                string = true;
                values += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                if b == b'{' {
                    objects += 1;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            b',' => values += 1,
            _ => {}
        }
        if depth > 2 * MAX_DEPTH + 8 || objects > MAX_RULES + 1 || values > 4 * MAX_ITEMS {
            return Err("sing-box JSON nesting/count limit exceeded".into());
        }
    }
    Ok(())
}

fn domain_pattern(value: &str, suffix: bool) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 253
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "*+/,\\<>".contains(c))
    {
        return Err("invalid sing-box domain value".into());
    }
    let labels = if suffix {
        value.strip_prefix('.').unwrap_or(value)
    } else {
        value
    };
    if labels.split('.').any(|s| s.is_empty() || s.len() > 63) {
        return Err("invalid sing-box domain labels".into());
    }
    if suffix && !value.starts_with('.') {
        Ok(format!("+.{value}"))
    } else {
        Ok(value.to_owned())
    }
}

fn compile_json(raw: SourceRule, depth: usize, budget: &mut Budget) -> Result<Node, String> {
    budget.node(depth)?;
    let domains = raw.domain.into_vec();
    let suffixes = raw.domain_suffix.into_vec();
    let keywords = raw.domain_keyword.into_vec();
    let regexes = raw.domain_regex.into_vec();
    let source = raw.source_ip_cidr.into_vec();
    let destination = raw.ip_cidr.into_vec();
    let total = domains.len()
        + suffixes.len()
        + keywords.len()
        + regexes.len()
        + source.len()
        + destination.len();
    budget.items(total)?;
    if raw.kind == "logical" {
        if total != 0 {
            return Err("logical rule cannot contain default address fields".into());
        }
        let and = match raw.mode.as_deref() {
            Some("and") => true,
            Some("or") => false,
            _ => return Err("logical rule requires and/or mode".into()),
        };
        let rules = raw.rules.ok_or("logical rule requires rules")?;
        if rules.is_empty() {
            return Err("logical rule must not be empty".into());
        }
        let rules = rules
            .into_iter()
            .map(|r| compile_json(r, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()?;
        let axes = rules.iter().fold(0, |a, n| a | n.axes);
        return Ok(Node {
            kind: NodeKind::Logical { and, rules },
            invert: raw.invert,
            axes,
        });
    }
    if !matches!(raw.kind.as_str(), "" | "default") || raw.mode.is_some() || raw.rules.is_some() {
        return Err("unknown rule type or logical fields on default rule".into());
    }
    if total == 0 {
        return Err("headless default rule requires conditions".into());
    }
    let mut rule = AddressRule::default();
    let mut axes = 0;
    if !domains.is_empty() || !suffixes.is_empty() {
        let mut builder = DomainRuleSetBuilder::new();
        for s in domains {
            builder.push_checked(&domain_pattern(&s, false)?)?;
        }
        for s in suffixes {
            builder.push_checked(&domain_pattern(&s, true)?)?;
        }
        rule.domains = Some(builder.build());
        axes |= 1;
    }
    if !keywords.is_empty() {
        if keywords.iter().any(String::is_empty) {
            return Err("empty domain keyword".into());
        }
        rule.keywords = keywords;
        axes |= 1;
    }
    if !regexes.is_empty() {
        rule.regexes = regexes
            .iter()
            .map(|s| budget.regex(s))
            .collect::<Result<_, _>>()?;
        axes |= 1;
    }
    if !source.is_empty() {
        rule.source = Some(parse_cidrs(source)?);
        axes |= 4;
    }
    if !destination.is_empty() {
        rule.destination = Some(parse_cidrs(destination)?);
        axes |= 2;
    }
    Ok(Node {
        kind: NodeKind::Address(Box::new(rule)),
        invert: raw.invert,
        axes,
    })
}

fn parse_cidrs(values: Vec<String>) -> Result<IpRangeSet, String> {
    let mut builder = IpRangeSetBuilder::new();
    for value in values {
        let net = value
            .parse::<ipnet::IpNet>()
            .or_else(|_| value.parse::<IpAddr>().map(ipnet::IpNet::from))
            .map_err(|_| "invalid headless IP/CIDR")?;
        builder.add(net);
    }
    Ok(builder.build())
}

/// Read the compressed SRS transport (versions 1–5), with a strict 64 MiB
/// decompressed ceiling. Unknown field tags and future versions fail closed.
pub fn from_srs(bytes: &[u8], behavior: RuleSetBehavior) -> Result<Box<dyn RuleSet>, String> {
    from_srs_bounded(bytes, behavior, MAX_BYTES)
}

fn from_srs_bounded(
    bytes: &[u8],
    behavior: RuleSetBehavior,
    max_decompressed: usize,
) -> Result<Box<dyn RuleSet>, String> {
    if bytes.len() > MAX_BYTES || !bytes.starts_with(b"SRS") || bytes.len() < 4 {
        return Err("invalid/oversize SRS header".into());
    }
    version(bytes[3])?;
    let mut decoder = flate2::Decompress::new(true);
    let mut data = Vec::new();
    let mut input = &bytes[4..];
    let mut scratch = [0u8; 16 * 1024];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(input, &mut scratch, flate2::FlushDecompress::None)
            .map_err(|e| format!("SRS zlib: {e}"))?;
        let consumed = (decoder.total_in() - before_in) as usize;
        let produced = (decoder.total_out() - before_out) as usize;
        if data
            .len()
            .checked_add(produced)
            .is_none_or(|n| n > max_decompressed)
        {
            return Err("SRS decompression exceeds configured byte limit".into());
        }
        data.extend_from_slice(&scratch[..produced]);
        input = &input[consumed..];
        if status == flate2::Status::StreamEnd {
            if !input.is_empty() {
                return Err("trailing SRS compressed data".into());
            }
            break;
        }
        // Requiring StreamEnd also verifies the zlib trailer/checksum;
        // Read::read_to_end alone can accept EOF before a missing trailer.
        if consumed == 0 && produced == 0 {
            return Err("truncated SRS zlib stream".into());
        }
    }
    let mut reader = DataReader::new(&data)?;
    let count = reader.count(MAX_RULES)?;
    let mut budget = Budget::default();
    let mut nodes = Vec::new();
    for _ in 0..count {
        nodes.push(read_node(&mut reader, 0, &mut budget)?);
    }
    reader.finish()?;
    finish(nodes, behavior)
}

fn read_node(
    reader: &mut DataReader<'_>,
    depth: usize,
    budget: &mut Budget,
) -> Result<Node, String> {
    budget.node(depth)?;
    match reader.byte()? {
        1 => {
            let and = match reader.byte()? {
                0 => true,
                1 => false,
                _ => return Err("invalid SRS logical mode".into()),
            };
            let count = reader.count(MAX_RULES)?;
            if count == 0 {
                return Err("empty SRS logical rule".into());
            }
            let mut rules = Vec::new();
            for _ in 0..count {
                rules.push(read_node(reader, depth + 1, budget)?);
            }
            let invert = reader.boolean()?;
            let axes = rules.iter().fold(0, |a, n| a | n.axes);
            Ok(Node {
                kind: NodeKind::Logical { and, rules },
                invert,
                axes,
            })
        }
        0 => {
            let mut rule = AddressRule::default();
            let mut seen = 0u32;
            let mut axes = 0;
            loop {
                let tag = reader.byte()?;
                if tag == 255 {
                    if seen == 0 {
                        return Err("empty SRS default rule".into());
                    }
                    return Ok(Node {
                        kind: NodeKind::Address(Box::new(rule)),
                        invert: reader.boolean()?,
                        axes,
                    });
                }
                if !(2..=6).contains(&tag) {
                    return Err(format!("unsupported SRS headless field tag {tag}; only domain/IP fields are supported"));
                }
                if seen & (1 << tag) != 0 {
                    return Err("duplicate SRS field".into());
                }
                seen |= 1 << tag;
                match tag {
                    2 => {
                        rule.domains = Some(read_domains(reader, budget)?);
                        axes |= 1;
                    }
                    3 | 4 => {
                        let count = reader.count(MAX_ITEMS)?;
                        budget.items(count)?;
                        if count == 0 {
                            return Err("empty SRS string field".into());
                        }
                        for _ in 0..count {
                            let value = reader.string()?;
                            if value.is_empty() {
                                return Err("empty SRS string item".into());
                            }
                            if tag == 3 {
                                rule.keywords.push(value.to_owned());
                            } else {
                                rule.regexes.push(budget.regex(value)?);
                            }
                        }
                        axes |= 1;
                    }
                    5 => {
                        rule.source = Some(read_ip_set(reader, budget)?);
                        axes |= 4;
                    }
                    6 => {
                        rule.destination = Some(read_ip_set(reader, budget)?);
                        axes |= 2;
                    }
                    _ => unreachable!(),
                }
            }
        }
        _ => Err("unknown SRS rule type".into()),
    }
}

fn read_domains(reader: &mut DataReader<'_>, budget: &mut Budget) -> Result<DomainRuleSet, String> {
    if reader.byte()? != 0 {
        return Err("unsupported sing-box domain-set version".into());
    }
    fn words(reader: &mut DataReader<'_>) -> Result<Vec<u64>, String> {
        let count = reader.count(MAX_BYTES / 8)?;
        // Prove the declared bytes exist before reserving memory.
        let bytes = reader.take(count.checked_mul(8).ok_or("bitmap size overflow")?)?;
        Ok(bytes
            .as_chunks::<8>()
            .0
            .iter()
            .copied()
            .map(u64::from_be_bytes)
            .collect())
    }
    let leaves = words(reader)?;
    let bitmap = words(reader)?;
    let label_count = reader.count(MAX_BYTES)?;
    let labels = reader.take(label_count)?;
    let mut builder = DomainRuleSetBuilder::new();
    let mut error = None;
    let mut count = 0usize;
    crate::mrs_parser::walk_sing_domain_set(&leaves, &bitmap, labels, |key| {
        if error.is_some() {
            return;
        }
        count += 1;
        if count > MAX_ITEMS - budget.items {
            error = Some("headless domain count exceeds limit".into());
            return;
        }
        let forward: String = key.chars().rev().collect();
        let parsed = if let Some(s) = forward.strip_prefix('\n') {
            domain_pattern(s, true)
        } else if let Some(s) = forward.strip_prefix('\r') {
            domain_pattern(s, true)
        } else {
            domain_pattern(&forward, false)
        };
        if let Err(e) = parsed.and_then(|s| builder.push_checked(&s)) {
            error = Some(e);
        }
    })?;
    if let Some(e) = error {
        return Err(e);
    }
    if count == 0 {
        return Err("empty sing-box domain matcher".into());
    }
    budget.items(count)?;
    Ok(builder.build())
}

fn read_ip_set(reader: &mut DataReader<'_>, budget: &mut Budget) -> Result<IpRangeSet, String> {
    if reader.byte()? != 1 {
        return Err("unsupported SRS IP-set version".into());
    }
    let count = usize::try_from(reader.u64_be()?).map_err(|_| "SRS range count overflow")?;
    budget.items(count)?;
    if count == 0 {
        return Err("empty SRS IP set".into());
    }
    let mut builder = IpRangeSetBuilder::new();
    fn address(reader: &mut DataReader<'_>) -> Result<IpAddr, String> {
        match reader.varint()? {
            4 => Ok(
                Ipv4Addr::from(<[u8; 4]>::try_from(reader.take(4)?).map_err(|_| "bad IPv4")?)
                    .into(),
            ),
            16 => Ok(Ipv6Addr::from(
                <[u8; 16]>::try_from(reader.take(16)?).map_err(|_| "bad IPv6")?,
            )
            .into()),
            _ => Err("invalid SRS address length".into()),
        }
    }
    for _ in 0..count {
        let from = address(reader)?;
        let to = address(reader)?;
        builder.add_range(from, to)?;
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn srs(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).unwrap();
        let mut out = b"SRS\x02".to_vec();
        out.extend(encoder.finish().unwrap());
        out
    }

    #[test]
    fn decompression_cap_and_zlib_truncation_or_trailing_bytes_fail() {
        let fixture = include_bytes!("../tests/fixtures/sing/headless-v2.srs");
        assert!(from_srs_bounded(fixture, RuleSetBehavior::Classical, 32)
            .err()
            .unwrap()
            .contains("byte limit"));
        for missing in 1..=5 {
            assert!(
                from_srs(
                    &fixture[..fixture.len() - missing],
                    RuleSetBehavior::Classical
                )
                .is_err(),
                "missing {missing}"
            );
        }
        let mut trailing = fixture.to_vec();
        trailing.push(0);
        assert!(from_srs(&trailing, RuleSetBehavior::Classical).is_err());
    }

    #[test]
    fn unknown_duplicate_fields_and_counts_are_rejected_before_allocation() {
        for data in [
            vec![1, 0, 7],
            vec![1, 0, 3, 1, 1, b'x', 3, 1, 1, b'y', 255, 0],
            vec![255; 12],
            vec![1, 0, 2, 0, 255, 255, 255, 127],
        ] {
            assert!(from_srs(&srs(&data), RuleSetBehavior::Classical).is_err());
        }
        let objects = vec![r#"{"domain":"a.example"}"#; MAX_RULES + 1].join(",");
        assert!(from_json(
            format!(r#"{{"version":2,"rules":[{objects}]}}"#).as_bytes(),
            RuleSetBehavior::Domain
        )
        .is_err());
        let mut nested = r#"{"domain":"a.example"}"#.to_owned();
        for _ in 0..MAX_DEPTH + 1 {
            nested = format!(r#"{{"type":"logical","mode":"and","rules":[{nested}]}}"#);
        }
        assert!(from_json(
            format!(r#"{{"version":2,"rules":[{nested}]}}"#).as_bytes(),
            RuleSetBehavior::Domain
        )
        .is_err());
    }
}
