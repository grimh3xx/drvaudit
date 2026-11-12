//! Turning driver records + intel into findings.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::enumerate::Driver;
use crate::intel::{BlockHit, LolDrivers, LolHit, MsBlocklist};
use crate::report::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Default)]
pub struct Verdict {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loldrivers: Option<LolHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms_blocklist: Option<BlockHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
}

/// Where a driver lives, judged against where the OS installs drivers.
pub fn classify_location(path: &str, os: Os) -> &'static str {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    match os {
        Os::Windows => {
            let sys = p.contains(r"\windows\system32\");
            if sys
                && (p.contains(r"\system32\drivers\")
                    || p.contains(r"\driverstore\filerepository\"))
            {
                "standard"
            } else if sys || p.contains(r"\windows\syswow64\") {
                "system"
            } else if [
                "\\users\\",
                "\\programdata\\",
                "\\temp\\",
                "\\appdata\\",
                "\\downloads\\",
                "\\$recycle.bin\\",
                "\\perflogs\\",
            ]
            .iter()
            .any(|d| p.contains(d))
            {
                "user-writable"
            } else {
                "non-standard"
            }
        }
        Os::Linux => {
            let p = path;
            if p.contains("/lib/modules/") {
                "standard"
            } else if p.starts_with("/tmp/")
                || p.starts_with("/dev/shm/")
                || p.starts_with("/home/")
                || p.starts_with("/var/tmp/")
            {
                "user-writable"
            } else {
                "non-standard"
            }
        }
    }
}

pub fn judge(d: &Driver, lol: Option<&LolDrivers>, ms: Option<&MsBlocklist>, os: Os) -> Verdict {
    let mut v = Verdict::default();
    let (a1, a256) =
        d.pe.as_ref()
            .map_or(("", ""), |p| (p.auth_sha1.as_str(), p.auth_sha256.as_str()));
    if let Some(l) = lol {
        v.loldrivers = l.lookup(&[&d.sha256, &d.sha1, &d.md5, a256, a1]);
    }
    if let Some(m) = ms {
        v.ms_blocklist = m.lookup_hash(&[a256, a1]).or_else(|| {
            let pe = d.pe.as_ref()?;
            m.lookup_name(
                pe.original_filename.as_deref()?,
                pe.file_version.as_deref(),
                &pe.chain_tbs,
                pe.signer.as_deref(),
            )
        });
    }
    v.location = d.path.as_deref().map(|p| classify_location(p, os));
    v
}

fn label(d: &Driver) -> String {
    d.path.clone().unwrap_or_else(|| d.name.clone())
}

pub fn findings(drivers: &[(Driver, Verdict)], os: Os) -> Vec<Finding> {
    let mut f = Vec::new();
    let mut catalog_only = Vec::new();
    let mut out_of_tree = Vec::new();
    let mut unsigned_kmods: Vec<(String, bool)> = Vec::new();

    for (d, v) in drivers {
        let src = label(d);
        if let Some(h) = &v.loldrivers {
            let malicious = h.category.contains("malicious");
            let mut fi = Finding::new(
                if malicious { "DRV-001" } else { "DRV-002" },
                if malicious { Severity::Critical } else { Severity::High },
                format!(
                    "{} {} driver: {}",
                    if d.loaded { "Loaded" } else { "Present" },
                    if malicious { "MALICIOUS" } else { "known-vulnerable" },
                    d.name
                ),
            )
            .detail(if malicious {
                "Hash matches a driver LOLDrivers classifies as malicious (rootkit / signed malware)."
            } else {
                "Hash matches a signed driver with known exploitable flaws. Attackers bring such drivers (BYOVD) to gain kernel read/write, kill EDR, or disable protections."
            })
            .evidence(format!("LOLDrivers {} · matched on {}", h.id, h.matched_on))
            .fix(if d.loaded {
                "Stop and remove the driver (sc stop / sc delete, or uninstall the vendor package), update to a fixed version, and enable the Microsoft vulnerable driver blocklist / HVCI. Investigate how it got there if it is not expected."
            } else {
                "Delete the file or update the vendor package; enable the Microsoft vulnerable driver blocklist."
            })
            .source(src.clone());
            if let Some(c) = &h.cve {
                fi = fi.evidence(c.clone());
            }
            f.push(fi);
        }
        if let Some(b) = &v.ms_blocklist {
            let exact = b.kind == "authenticode hash";
            f.push(
                Finding::new(
                    if exact { "DRV-003" } else { "DRV-004" },
                    if exact { Severity::High } else { Severity::Medium },
                    format!("{} is on the Microsoft vulnerable driver blocklist", d.name),
                )
                .detail(if exact {
                    "Its Authenticode hash is denied by Microsoft's recommended driver block rules. If it is loaded, the blocklist is not being enforced on this system."
                } else {
                    "OriginalFilename, version and signing CA (TBS hash) match a deny rule. Not as exact as a hash rule (the policy also has page-hash variants), but the signer binding was verified."
                })
                .evidence(format!("rule \"{}\" ({})", b.rule, b.kind))
                .fix("Update or remove the driver; enable 'Microsoft Vulnerable Driver Blocklist' (Windows Security → Core isolation).")
                .source(src.clone()),
            );
        }

        if d.loaded && !d.on_disk && d.path.is_some() {
            f.push(
                Finding::new("DRV-009", Severity::Medium, format!("Loaded driver has no file on disk: {}", d.name))
                    .detail("The image backing a running kernel module is gone — deleted after load, which is a common anti-forensics step.")
                    .fix("Capture memory for analysis before rebooting; identify the service that loaded it.")
                    .source(src.clone()),
            );
        }
        if let Some(e) = &d.read_error {
            f.push(
                Finding::new(
                    "DRV-014",
                    Severity::Info,
                    format!("Could not read {}", d.name),
                )
                .detail(e.clone())
                .source(src.clone()),
            );
        }

        match v.location {
            Some("user-writable") => f.push(
                Finding::new("DRV-008", Severity::High, format!("Driver {} from a user-writable directory", if d.loaded { "loaded" } else { "stored" }))
                    .detail("Drivers belong under the OS driver store. Kernel code staged in user/temp directories is a hallmark of BYOVD tooling.")
                    .evidence(src.clone())
                    .fix("Identify the service/process that loaded it and remove it; check for persistence.")
                    .source(src.clone()),
            ),
            Some("non-standard") if d.loaded => f.push(
                Finding::new("DRV-008", Severity::Medium, format!("Driver loaded from a non-standard path: {}", d.name))
                    .detail("Legitimate drivers normally load from System32\\drivers / DriverStore (Windows) or /lib/modules (Linux).")
                    .evidence(src.clone())
                    .fix("Confirm the vendor and installation; move it under the driver store or remove it.")
                    .source(src.clone()),
            ),
            _ => {}
        }

        if let Some(pe) = &d.pe {
            if !pe.signed {
                if os == Os::Windows && matches!(v.location, Some("standard" | "system")) {
                    catalog_only.push(d.name.clone());
                } else {
                    f.push(
                        Finding::new("DRV-005", if d.loaded { Severity::High } else { Severity::Medium }, format!("Driver without an embedded signature: {}", d.name))
                            .detail(if d.loaded {
                                "Outside the driver store and not Authenticode-signed: either it is catalog-signed by an unusual installer, or code integrity was bypassed to load it."
                            } else {
                                "No embedded Authenticode signature; Windows will refuse it unless a catalog vouches for it or DSE is off."
                            })
                            .fix("Verify with `signtool verify /pa /kp` or Get-AuthenticodeSignature; remove if unsigned.")
                            .source(src.clone()),
                    );
                }
            }
        }
        if d.kmod_sig.as_ref().is_some_and(|s| !s.signed) {
            unsigned_kmods.push((d.name.clone(), d.loaded));
        }
        if let Some(t) = &d.taint {
            if t.contains('F') {
                f.push(
                    Finding::new("DRV-007", Severity::High, format!("Module force-loaded: {}", d.name))
                        .detail("Taint 'F': loaded with --force, bypassing version magic checks — typical of out-of-tree rootkits.")
                        .evidence(format!("taint ({t})"))
                        .source(src.clone()),
                );
            }
            if t.contains('O') {
                out_of_tree.push(format!("{} ({t})", d.name));
            }
        }
    }

    if !catalog_only.is_empty() {
        let mut fi = Finding::new("DRV-015", Severity::Info, format!("{} driver(s) rely on catalog signing", catalog_only.len()))
            .detail("No embedded Authenticode signature; inbox Windows drivers are normally signed via security catalogs, which drvaudit does not evaluate.");
        for n in catalog_only.iter().take(12) {
            fi = fi.evidence(n.clone());
        }
        f.push(fi);
    }
    if !unsigned_kmods.is_empty() {
        let loaded = unsigned_kmods.iter().any(|(_, l)| *l);
        let mut fi = Finding::new(
            "DRV-006",
            if loaded { Severity::Medium } else { Severity::Low },
            format!("{} unsigned kernel module(s)", unsigned_kmods.len()),
        )
        .detail("No appended module signature. Unless sig_enforce/lockdown is on, the kernel loads them anyway — the entry path for LKM rootkits. If every module is unsigned the kernel was built without CONFIG_MODULE_SIG.")
        .fix("Use a kernel with module signing; sign DKMS modules with an enrolled MOK (scripts/sign-file) and boot with module.sig_enforce=1.");
        for (n, _) in unsigned_kmods.iter().take(15) {
            fi = fi.evidence(n.clone());
        }
        f.push(fi);
    }
    if !out_of_tree.is_empty() {
        let mut fi = Finding::new("DRV-016", Severity::Info, format!("{} out-of-tree module(s) loaded", out_of_tree.len()))
            .detail("Externally built modules (DKMS, vendor drivers) are outside the distribution's review and update stream.");
        for n in out_of_tree {
            fi = fi.evidence(n);
        }
        f.push(fi);
    }
    f
}

pub fn intel_missing(lol: bool, ms: bool, errs: &[String]) -> Option<Finding> {
    if lol && ms {
        return None;
    }
    let mut fi = Finding::new("DRV-013", Severity::Info, "Threat-intel feeds not fully loaded")
        .detail("Without LOLDrivers and the Microsoft blocklist only structural checks run.")
        .fix("Run `drvaudit update` (downloads both feeds into the local cache), or pass --loldrivers / --blocklist.");
    for e in errs {
        fi = fi.evidence(e.clone());
    }
    Some(fi)
}

pub fn cross_view(hidden_from_proc: &[String], hidden_from_sysfs: &[String]) -> Vec<Finding> {
    let mut f = Vec::new();
    for m in hidden_from_proc {
        f.push(
            Finding::new("DRV-010", Severity::Critical, format!("Module hidden from /proc/modules: {m}"))
                .detail("A loaded module has a sysfs kobject (/sys/module/<name>/initstate) but is missing from the module list. Unlinking from the list is the classic LKM-rootkit hiding technique (e.g. Diamorphine, Reptile).")
                .fix("Treat the host as compromised: capture memory (LiME/AVML), isolate it, and rebuild from known-good media.")
                .source(format!("/sys/module/{m}")),
        );
    }
    for m in hidden_from_sysfs {
        f.push(
            Finding::new("DRV-010", Severity::High, format!("Module missing its sysfs kobject: {m}"))
                .detail("Listed in /proc/modules but /sys/module/<name> is gone — the kobject was removed to hide from sysfs-based tooling.")
                .fix("Investigate as a possible rootkit; capture memory before rebooting.")
                .source("/proc/modules"),
        );
    }
    f
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub name: String,
    pub path: Option<String>,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub tool: String,
    pub host: Option<String>,
    pub created: u64,
    pub drivers: Vec<BaselineEntry>,
}

pub fn make_baseline(drivers: &[(Driver, Verdict)], host: Option<String>) -> Baseline {
    Baseline {
        tool: format!("drvaudit {}", env!("CARGO_PKG_VERSION")),
        host,
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        drivers: drivers
            .iter()
            .map(|(d, _)| BaselineEntry {
                name: d.name.clone(),
                path: d.path.clone(),
                sha256: d.sha256.clone(),
            })
            .collect(),
    }
}

fn key(name: &str) -> String {
    name.to_ascii_lowercase()
}

pub fn diff(base: &Baseline, now: &[(Driver, Verdict)]) -> Vec<Finding> {
    let old: HashMap<String, &BaselineEntry> =
        base.drivers.iter().map(|e| (key(&e.name), e)).collect();
    let new: HashMap<String, &Driver> = now.iter().map(|(d, _)| (key(&d.name), d)).collect();
    let mut f = Vec::new();
    for (k, d) in &new {
        match old.get(k) {
            None => f.push(
                Finding::new("DRV-011", Severity::Medium, format!("New driver since baseline: {}", d.name))
                    .detail("Not present when the baseline was taken.")
                    .evidence(format!("sha256 {}", d.sha256))
                    .fix("Confirm it belongs to a sanctioned install/update; otherwise investigate.")
                    .source(label(d)),
            ),
            Some(b) if !b.sha256.is_empty() && !d.sha256.is_empty() && b.sha256 != d.sha256 => f.push(
                Finding::new("DRV-012", Severity::High, format!("Driver binary changed since baseline: {}", d.name))
                    .detail("Same driver name, different file hash. Expected after a driver update — otherwise a sign of replacement.")
                    .evidence(format!("was {}", b.sha256))
                    .evidence(format!("now {}", d.sha256))
                    .fix("Correlate with update history (Windows Update / package manager logs).")
                    .source(label(d)),
            ),
            _ => {}
        }
    }
    for (k, b) in &old {
        if !new.contains_key(k) {
            f.push(
                Finding::new(
                    "DRV-017",
                    Severity::Info,
                    format!("Driver gone since baseline: {}", b.name),
                )
                .source(b.path.clone().unwrap_or_else(|| b.name.clone())),
            );
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        assert_eq!(
            classify_location(r"C:\Windows\System32\drivers\acpi.sys", Os::Windows),
            "standard"
        );
        assert_eq!(
            classify_location(
                r"C:\Windows\System32\DriverStore\FileRepository\x\y.sys",
                Os::Windows
            ),
            "standard"
        );
        assert_eq!(
            classify_location(r"C:\Windows\System32\ntoskrnl.exe", Os::Windows),
            "system"
        );
        assert_eq!(
            classify_location(r"C:\Users\bob\AppData\Local\Temp\x.sys", Os::Windows),
            "user-writable"
        );
        assert_eq!(
            classify_location(r"C:\Program Files\Vendor\v.sys", Os::Windows),
            "non-standard"
        );
        assert_eq!(
            classify_location("/lib/modules/6.1/kernel/x.ko", Os::Linux),
            "standard"
        );
        assert_eq!(classify_location("/tmp/x.ko", Os::Linux), "user-writable");
    }

    fn drv(name: &str, sha: &str) -> (Driver, Verdict) {
        (
            Driver {
                name: name.into(),
                sha256: sha.into(),
                ..Default::default()
            },
            Verdict::default(),
        )
    }

    #[test]
    fn baseline_diff() {
        let base = make_baseline(&[drv("a.sys", "11"), drv("b.sys", "22")], None);
        let now = [drv("A.sys", "11"), drv("b.sys", "33"), drv("c.sys", "44")];
        let f = diff(&base, &now);
        let ids: Vec<&str> = f.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"DRV-011"));
        assert!(ids.contains(&"DRV-012"));
        assert!(!ids.contains(&"DRV-017"));
    }

    #[test]
    fn unsigned_inbox_driver_is_aggregated_not_flagged() {
        let mut d = Driver {
            name: "acpi.sys".into(),
            path: Some(r"C:\Windows\System32\drivers\acpi.sys".into()),
            loaded: true,
            on_disk: true,
            ..Default::default()
        };
        d.pe = Some(Default::default());
        let v = Verdict {
            location: Some("standard"),
            ..Default::default()
        };
        let f = findings(&[(d, v)], Os::Windows);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "DRV-015");
    }
}
