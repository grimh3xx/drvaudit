//! Threat-intel feeds: LOLDrivers (loldrivers.io) and Microsoft's recommended
//! vulnerable driver blocklist (App Control SiPolicy XML). Both are cached
//! locally by `drvaudit update`; audits never touch the network.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::pe::version_cmp;

pub const LOLDRIVERS_URL: &str = "https://www.loldrivers.io/api/drivers.json";
pub const MS_BLOCKLIST_URL: &str = "https://aka.ms/VulnerableDriverBlockList";

#[derive(Debug, Clone, Serialize)]
pub struct LolHit {
    pub id: String,
    pub category: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    pub matched_on: &'static str,
}

#[derive(Default)]
pub struct LolDrivers {
    by_hash: HashMap<String, (usize, &'static str)>,
    entries: Vec<(String, String, String, Option<String>)>,
    pub source: Option<String>,
}

impl LolDrivers {
    pub fn parse(json: &str, source: impl Into<String>) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(json).context("LOLDrivers JSON")?;
        let arr = v.as_array().context("LOLDrivers: expected a JSON array")?;
        let mut me = Self {
            source: Some(source.into()),
            ..Default::default()
        };
        for d in arr {
            let id = d["Id"].as_str().unwrap_or("").to_string();
            let category = d["Category"]
                .as_str()
                .unwrap_or("vulnerable driver")
                .to_ascii_lowercase();
            let name = d["Tags"]
                .as_array()
                .and_then(|t| t.first())
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let cve = d["CVE"]
                .as_array()
                .map(|c| {
                    c.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|s| !s.is_empty());
            let idx = me.entries.len();
            me.entries.push((id, category, name, cve));
            for s in d["KnownVulnerableSamples"].as_array().into_iter().flatten() {
                for (k, tag) in [("MD5", "md5"), ("SHA1", "sha1"), ("SHA256", "sha256")] {
                    if let Some(h) = s[k].as_str().filter(|h| !h.is_empty() && *h != "-") {
                        me.by_hash.insert(h.to_ascii_lowercase(), (idx, tag));
                    }
                }
                if let Some(a) = s["Authentihash"].as_object() {
                    for (k, tag) in [
                        ("SHA1", "authentihash-sha1"),
                        ("SHA256", "authentihash-sha256"),
                    ] {
                        if let Some(h) = a
                            .get(k)
                            .and_then(|h| h.as_str())
                            .filter(|h| !h.is_empty() && *h != "-")
                        {
                            me.by_hash.insert(h.to_ascii_lowercase(), (idx, tag));
                        }
                    }
                }
            }
        }
        Ok(me)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn hashes(&self) -> usize {
        self.by_hash.len()
    }

    pub fn lookup(&self, hashes: &[&str]) -> Option<LolHit> {
        hashes.iter().filter(|h| !h.is_empty()).find_map(|h| {
            let (idx, tag) = self.by_hash.get(&h.to_ascii_lowercase())?;
            let (id, category, name, cve) = &self.entries[*idx];
            Some(LolHit {
                id: id.clone(),
                category: category.clone(),
                name: name.clone(),
                cve: cve.clone(),
                matched_on: tag,
            })
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockHit {
    pub rule: String,
    pub kind: &'static str,
}

struct NameRule {
    id: String,
    file: String,
    min: Option<String>,
    max: Option<String>,
    friendly: String,
}

/// An App Control <Signer>: a CA identified by its TBS hash, optionally
/// narrowed to a leaf publisher CN.
#[derive(Clone)]
struct SignerSpec {
    root_tbs: String,
    publisher: Option<String>,
}

#[derive(Default)]
pub struct MsBlocklist {
    hashes: HashMap<String, String>,
    names: Vec<NameRule>,
    signers: HashMap<String, Vec<SignerSpec>>,
    pub version: Option<String>,
    pub source: Option<String>,
}

impl MsBlocklist {
    pub fn parse(xml: &str, source: impl Into<String>) -> Result<Self> {
        let doc = roxmltree::Document::parse(xml).context("blocklist XML")?;
        let mut me = Self {
            source: Some(source.into()),
            ..Default::default()
        };
        for n in doc.descendants().filter(|n| n.is_element()) {
            match n.tag_name().name() {
                "VersionEx" => me.version = n.text().map(str::to_string),
                "Deny" | "FileAttrib" => {
                    let friendly = n
                        .attribute("FriendlyName")
                        .or(n.attribute("ID"))
                        .unwrap_or("")
                        .to_string();
                    if let Some(h) = n.attribute("Hash") {
                        me.hashes.insert(h.to_ascii_lowercase(), friendly);
                    } else if let Some(f) = n.attribute("FileName") {
                        me.names.push(NameRule {
                            id: n.attribute("ID").unwrap_or("").to_string(),
                            file: f.to_ascii_lowercase(),
                            min: n.attribute("MinimumFileVersion").map(str::to_string),
                            max: n.attribute("MaximumFileVersion").map(str::to_string),
                            friendly,
                        });
                    }
                }
                "Signer" => {
                    let child = |tag: &str| n.children().find(|c| c.tag_name().name() == tag);
                    let Some(root) = child("CertRoot").and_then(|c| c.attribute("Value")) else {
                        continue;
                    };
                    let spec = SignerSpec {
                        root_tbs: root.to_ascii_lowercase(),
                        publisher: child("CertPublisher")
                            .and_then(|c| c.attribute("Value"))
                            .map(str::to_string),
                    };
                    for r in n
                        .children()
                        .filter(|c| c.tag_name().name() == "FileAttribRef")
                    {
                        if let Some(id) = r.attribute("RuleID") {
                            me.signers
                                .entry(id.to_string())
                                .or_default()
                                .push(spec.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        if me.hashes.is_empty() && me.names.is_empty() {
            bail!("no Deny/FileAttrib rules found — not a SiPolicy blocklist?");
        }
        Ok(me)
    }

    pub fn rules(&self) -> usize {
        self.hashes.len() + self.names.len()
    }

    /// Hash rules use the flat Authenticode SHA-1 / SHA-256 digest.
    pub fn lookup_hash(&self, auth: &[&str]) -> Option<BlockHit> {
        auth.iter().find_map(|h| {
            self.hashes.get(&h.to_ascii_lowercase()).map(|r| BlockHit {
                rule: r.clone(),
                kind: "authenticode hash",
            })
        })
    }

    /// FileAttrib rules pair OriginalFilename + a version window with the
    /// signers that reference them. A match requires the driver's embedded
    /// certificate chain to contain the signer's CA (by TBS hash) and, when the
    /// rule names one, the leaf publisher. Catalog-signed files cannot be
    /// verified this way and never match.
    pub fn lookup_name(
        &self,
        original: &str,
        version: Option<&str>,
        chain_tbs: &[String],
        leaf: Option<&str>,
    ) -> Option<BlockHit> {
        let file = original.to_ascii_lowercase();
        self.names.iter().find_map(|r| {
            if r.file != file {
                return None;
            }
            let v = version?;
            let above = r.min.as_deref().is_none_or(|m| version_cmp(v, m).is_ge());
            let below = r.max.as_deref().is_none_or(|m| version_cmp(v, m).is_le());
            if !(above && below) {
                return None;
            }
            let signed_by = match self.signers.get(&r.id) {
                None => true,
                Some(specs) => specs.iter().any(|s| {
                    chain_tbs.contains(&s.root_tbs)
                        && s.publisher
                            .as_deref()
                            .is_none_or(|p| leaf.is_some_and(|l| l.eq_ignore_ascii_case(p)))
                }),
            };
            signed_by.then(|| BlockHit {
                rule: r.friendly.clone(),
                kind: "file name + version + signer",
            })
        })
    }
}

pub fn cache_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("DRVAUDIT_CACHE") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")));
    base.unwrap_or_else(std::env::temp_dir).join("drvaudit")
}

pub const LOL_FILE: &str = "loldrivers.json";
pub const MS_FILE: &str = "SiPolicy_Enforced.xml";

fn fetch(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .set(
            "User-Agent",
            concat!("drvaudit/", env!("CARGO_PKG_VERSION")),
        )
        .timeout(std::time::Duration::from_secs(60))
        .call()
        .with_context(|| format!("GET {url}"))?;
    let mut body = Vec::new();
    resp.into_reader()
        .take(128 * 1024 * 1024)
        .read_to_end(&mut body)?;
    Ok(body)
}

/// Download both feeds into `dir`. Returns human-readable status lines.
pub fn update(dir: &Path) -> Result<Vec<String>> {
    std::fs::create_dir_all(dir)?;
    let mut log = Vec::new();

    let lol = fetch(LOLDRIVERS_URL)?;
    let parsed = LolDrivers::parse(std::str::from_utf8(&lol)?, LOLDRIVERS_URL)?;
    std::fs::write(dir.join(LOL_FILE), &lol)?;
    log.push(format!(
        "LOLDrivers: {} drivers, {} hashes",
        parsed.len(),
        parsed.hashes()
    ));

    let zip_bytes = fetch(MS_BLOCKLIST_URL)?;
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("blocklist zip")?;
    let name = (0..z.len())
        .filter_map(|i| z.by_index(i).ok().map(|f| f.name().to_string()))
        // Shipped as SiPolicy_Enforced.xml, renamed DriverPolicy_Enforced.xml in 2025.
        .filter(|n| n.ends_with("_Enforced.xml") && !n.contains("Legacy"))
        .min_by_key(|n| !n.contains("DriverPolicy"))
        .context("no *_Enforced.xml policy found in the blocklist archive")?;
    let mut xml = String::new();
    z.by_name(&name)?.read_to_string(&mut xml)?;
    let parsed = MsBlocklist::parse(&xml, MS_BLOCKLIST_URL)?;
    std::fs::write(dir.join(MS_FILE), &xml)?;
    log.push(format!(
        "Microsoft blocklist {}: {} rules",
        parsed.version.as_deref().unwrap_or("?"),
        parsed.rules()
    ));
    Ok(log)
}

pub fn load(
    dir: &Path,
    lol: Option<&Path>,
    ms: Option<&Path>,
) -> (Option<LolDrivers>, Option<MsBlocklist>, Vec<String>) {
    let mut errs = Vec::new();
    let lol_path = lol
        .map(Path::to_path_buf)
        .unwrap_or_else(|| dir.join(LOL_FILE));
    let ms_path = ms
        .map(Path::to_path_buf)
        .unwrap_or_else(|| dir.join(MS_FILE));
    let lol = std::fs::read_to_string(&lol_path)
        .map_err(anyhow::Error::from)
        .and_then(|s| LolDrivers::parse(&s, lol_path.display().to_string()))
        .map_err(|e| errs.push(format!("LOLDrivers ({}): {e:#}", lol_path.display())))
        .ok();
    let ms = std::fs::read_to_string(&ms_path)
        .map_err(anyhow::Error::from)
        .and_then(|s| MsBlocklist::parse(&s, ms_path.display().to_string()))
        .map_err(|e| errs.push(format!("MS blocklist ({}): {e:#}", ms_path.display())))
        .ok();
    (lol, ms, errs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOL: &str = r#"[
      {"Id":"abc-1","Category":"vulnerable driver","Tags":["evil.sys"],"CVE":["CVE-2099-0001"],
       "KnownVulnerableSamples":[{"MD5":"AAAA","SHA1":"-","SHA256":"BBBB","Authentihash":{"SHA256":"CCCC"}}]},
      {"Id":"def-2","Category":"malicious","Tags":["rk.sys"],"KnownVulnerableSamples":[{"SHA256":"dddd"}]}
    ]"#;

    #[test]
    fn loldrivers_index() {
        let l = LolDrivers::parse(LOL, "t").unwrap();
        assert_eq!(l.len(), 2);
        let h = l.lookup(&["", "cccc"]).unwrap();
        assert_eq!(
            (h.id.as_str(), h.matched_on),
            ("abc-1", "authentihash-sha256")
        );
        assert_eq!(h.cve.as_deref(), Some("CVE-2099-0001"));
        assert_eq!(l.lookup(&["DDDD"]).unwrap().category, "malicious");
        assert!(l.lookup(&["-"]).is_none());
    }

    const XML: &str = r#"<?xml version="1.0"?>
      <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy"><VersionEx>10.1.0.0</VersionEx>
      <FileRules>
        <Deny ID="ID_DENY_A" FriendlyName="bad.sys Hash Sha256" Hash="ABCDEF"/>
        <FileAttrib ID="ID_FILEATTRIB_B" FriendlyName="old.sys" FileName="old.sys" MaximumFileVersion="2.0.0.0"/>
      </FileRules>
      <Signers><Signer ID="S1" Name="Some CA"><CertRoot Type="TBS" Value="AABB"/><CertPublisher Value="Vendor Inc"/>
        <FileAttribRef RuleID="ID_FILEATTRIB_B"/></Signer></Signers></SiPolicy>"#;

    #[test]
    fn blocklist_rules() {
        let b = MsBlocklist::parse(XML, "t").unwrap();
        assert_eq!(b.version.as_deref(), Some("10.1.0.0"));
        assert_eq!(b.rules(), 2);
        assert!(b.lookup_hash(&["abcdef"]).is_some());
        let chain = vec!["aabb".to_string()];
        assert!(b
            .lookup_name("OLD.SYS", Some("1.9"), &chain, Some("vendor inc"))
            .is_some());
        // Same name/version, different signer (e.g. an inbox Microsoft driver).
        assert!(b
            .lookup_name("old.sys", Some("1.9"), &chain, Some("Microsoft Windows"))
            .is_none());
        assert!(b.lookup_name("old.sys", Some("1.9"), &[], None).is_none());
        assert!(b
            .lookup_name("old.sys", Some("2.0.0.1"), &chain, Some("Vendor Inc"))
            .is_none());
        assert!(b
            .lookup_name("old.sys", None, &chain, Some("Vendor Inc"))
            .is_none());
    }

    #[test]
    fn rejects_unrelated_xml() {
        assert!(MsBlocklist::parse("<a/>", "t").is_err());
    }
}
