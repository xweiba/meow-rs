//! Legacy sing-box GeoSite DB v0: borrowed directory/sections, allowlisted
//! category allocation. Upstream v1.11.0 common/geosite/{reader,writer,rule}.go.
use crate::data_reader::{DataReader, MAX_BYTES, MAX_ITEMS};
use crate::geosite::GeositeDB;
use std::collections::{HashMap, HashSet};

pub(crate) fn from_bytes(
    data: &[u8],
    allowed: Option<&HashSet<String>>,
) -> Result<GeositeDB, String> {
    let mut r = DataReader::new(data)?;
    if r.byte()? != 0 {
        return Err("unsupported sing-box GeoSite DB version (expected 0)".into());
    }
    let count = r.count(65_536)?;
    if count == 0 {
        return Err("empty sing-box GeoSite directory".into());
    }
    let mut directory = Vec::new();
    let mut seen = HashSet::new();
    let mut total = 0usize;
    for _ in 0..count {
        let name = r.string()?;
        if name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || !seen.insert(name.to_ascii_lowercase())
        {
            return Err("invalid/duplicate GeoSite category".into());
        }
        let offset = r.count(MAX_BYTES)?;
        let items = r.count(MAX_ITEMS)?;
        total = total.checked_add(items).ok_or("GeoSite count overflow")?;
        if total > MAX_ITEMS {
            return Err("GeoSite domain count exceeds limit".into());
        }
        directory.push((name, offset, items));
    }
    let body = &data[r.pos..];
    let mut categories = HashMap::new();
    let mut counts = HashMap::new();
    let mut regexes = HashMap::new();
    let mut keywords = HashMap::new();
    let mut regex_bytes = 0usize;
    let mut regex_count = 0usize;
    for (i, &(name, offset, items)) in directory.iter().enumerate() {
        let end = directory.get(i + 1).map_or(body.len(), |entry| entry.1);
        if (i == 0 && offset != 0) || offset > end || end > body.len() {
            return Err("invalid GeoSite category offsets".into());
        }
        let mut section = DataReader::new(&body[offset..end])?;
        let key = name.to_ascii_lowercase();
        let load = allowed.is_none_or(|a| a.iter().any(|s| s.eq_ignore_ascii_case(&key)));
        if load {
            categories
                .entry(key.clone())
                .or_insert_with(meow_trie::DomainTrie::new);
            counts.insert(key.clone(), items);
        }
        for _ in 0..items {
            let tag = section.byte()?;
            let value = section.string()?;
            if tag > 3 {
                return Err(format!("unknown sing-box GeoSite item type {tag}"));
            }
            if value.is_empty() {
                return Err("empty sing-box GeoSite value".into());
            }
            if !load {
                continue;
            }
            match tag {
                0 | 1 => {
                    let pattern = if tag == 1 && !value.starts_with('.') {
                        format!("+.{value}")
                    } else {
                        value.to_owned()
                    };
                    if value.len() > 253
                        || value
                            .chars()
                            .any(|c| c.is_control() || c.is_whitespace() || "*+/,\\<>".contains(c))
                    {
                        return Err("invalid GeoSite domain".into());
                    }
                    let trie = categories.get_mut(&key).expect("loaded category");
                    trie.insert(&pattern, ());
                    if let Some(root) = pattern.strip_prefix("+.") {
                        trie.insert(root, ());
                    }
                }
                2 => keywords
                    .entry(key.clone())
                    .or_insert_with(Vec::new)
                    .push(value.to_owned()),
                3 => {
                    regex_bytes += value.len();
                    regex_count += 1;
                    if regex_bytes > 1024 * 1024 || regex_count > 128 {
                        return Err("GeoSite regex budget exceeded".into());
                    }
                    regex::RegexBuilder::new(value)
                        .size_limit(256 * 1024)
                        .dfa_size_limit(64 * 1024)
                        .build()
                        .map_err(|e| format!("GeoSite regex: {e}"))?;
                    regexes
                        .entry(key.clone())
                        .or_insert_with(Vec::new)
                        .push(value.to_owned());
                }
                _ => unreachable!(),
            }
        }
        section.finish()?;
    }
    Ok(GeositeDB::from_parts(categories, counts, regexes, keywords))
}
