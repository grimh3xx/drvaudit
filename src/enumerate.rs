//! Collecting drivers: loaded kernel modules on the running system, or files
//! on disk. Every collected item is hashed and parsed the same way.

use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::pe::{self, PeInfo};

#[derive(Debug, Clone, Serialize, Default)]
pub struct KoSig {
    pub signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algo: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Driver {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub loaded: bool,
    pub on_disk: bool,
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kmod_sig: Option<KoSig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
}

const MAX_FILE: u64 = 256 * 1024 * 1024;

/// Hash + parse the file behind a driver record (if any).
pub fn inspect(d: &mut Driver) {
    let Some(path) = d.path.clone() else { return };
    let data = match std::fs::metadata(&path).and_then(|m| {
        if m.len() > MAX_FILE {
            Err(std::io::Error::other("file too large"))
        } else {
            std::fs::read(&path)
        }
    }) {
        Ok(b) => b,
        Err(e) => {
            d.on_disk = e.kind() != std::io::ErrorKind::NotFound;
            if d.on_disk {
                d.read_error = Some(e.to_string());
            }
            return;
        }
    };
    d.on_disk = true;
    d.size = data.len() as u64;
    d.md5 = hex::encode(md5::Md5::digest(&data));
    d.sha1 = hex::encode(Sha1::digest(&data));
    d.sha256 = hex::encode(Sha256::digest(&data));
    if pe::is_pe(&data) {
        d.pe = pe::parse(&data);
    } else if is_kmod_name(&path) {
        d.kmod_sig = Some(kmod_signature(&path, &data));
    }
}

pub fn is_kmod_name(p: &str) -> bool {
    [".ko", ".ko.xz", ".ko.zst", ".ko.gz"]
        .iter()
        .any(|e| p.ends_with(e))
}

const KMOD_MAGIC: &[u8] = b"~Module signature appended~\n";

fn decompress(path: &str, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if path.ends_with(".zst") {
        ruzstd::StreamingDecoder::new(data)
            .ok()?
            .read_to_end(&mut out)
            .ok()?;
    } else if path.ends_with(".xz") {
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut out).ok()?;
    } else if path.ends_with(".gz") {
        flate2::read::GzDecoder::new(data)
            .read_to_end(&mut out)
            .ok()?;
    } else {
        return None;
    }
    Some(out)
}

/// Kernel modules are signed before compression: the PKCS#7 blob, a 12-byte
/// `struct module_signature`, then the magic string close the ELF.
pub fn kmod_signature(path: &str, data: &[u8]) -> KoSig {
    let raw;
    let elf = if data.starts_with(b"\x7fELF") {
        data
    } else {
        match decompress(path, data) {
            Some(d) => {
                raw = d;
                &raw
            }
            None => return KoSig::default(),
        }
    };
    if !elf.ends_with(KMOD_MAGIC) {
        return KoSig::default();
    }
    let end = elf.len() - KMOD_MAGIC.len();
    let Some(ms) = end.checked_sub(12).and_then(|s| elf.get(s..end)) else {
        return KoSig {
            signed: true,
            ..Default::default()
        };
    };
    let sig_len = u32::from_be_bytes([ms[8], ms[9], ms[10], ms[11]]) as usize;
    let blob = (end - 12)
        .checked_sub(sig_len)
        .and_then(|s| elf.get(s..end - 12))
        .unwrap_or(&[]);
    KoSig {
        signed: true,
        signer: issuer_cn(blob),
        hash_algo: digest_oid(blob),
    }
}

/// First commonName in the CMS SignerInfo (issuer of the signing key).
fn issuer_cn(blob: &[u8]) -> Option<String> {
    const CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let at = blob.windows(CN.len()).position(|w| w == CN)? + CN.len();
    let tag = *blob.get(at)?;
    let len = *blob.get(at + 1)? as usize;
    if !matches!(tag, 0x0c | 0x13 | 0x14 | 0x16) || len > 0x7f {
        return None;
    }
    std::str::from_utf8(blob.get(at + 2..at + 2 + len)?)
        .ok()
        .map(str::to_string)
}

fn digest_oid(blob: &[u8]) -> Option<&'static str> {
    // 2.16.840.1.101.3.4.2.{1,2,3}
    const NIST: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];
    let at = blob.windows(NIST.len()).position(|w| w == NIST)? + NIST.len();
    match blob.get(at)? {
        1 => Some("sha256"),
        2 => Some("sha384"),
        3 => Some("sha512"),
        _ => None,
    }
}

fn kmod_key(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    let base = base.split(".ko").next().unwrap_or(base);
    base.replace('-', "_")
}

pub struct LinuxView {
    pub drivers: Vec<Driver>,
    /// Modules with a sysfs kobject (initstate) that /proc/modules omits.
    pub hidden_from_proc: Vec<String>,
    /// Modules in /proc/modules without a sysfs kobject.
    pub hidden_from_sysfs: Vec<String>,
    pub modules_dir: Option<PathBuf>,
}

pub fn linux_loaded(root: &Path) -> LinuxView {
    let rd = |p: &str| std::fs::read_to_string(root.join(p.trim_start_matches('/'))).ok();
    let release = rd("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string());
    let modules_dir = release.as_ref().and_then(|r| {
        [format!("lib/modules/{r}"), format!("usr/lib/modules/{r}")]
            .into_iter()
            .map(|p| root.join(p))
            .find(|p| p.is_dir())
    });
    let mut paths: HashMap<String, PathBuf> = HashMap::new();
    if let Some(dir) = &modules_dir {
        if let Ok(dep) = std::fs::read_to_string(dir.join("modules.dep")) {
            for line in dep.lines() {
                if let Some((rel, _)) = line.split_once(':') {
                    paths.insert(kmod_key(rel), dir.join(rel));
                }
            }
        }
    }

    let mut drivers = Vec::new();
    let mut in_proc = BTreeSet::new();
    for line in rd("/proc/modules").unwrap_or_default().lines() {
        let mut f = line.split_whitespace();
        let Some(name) = f.next() else { continue };
        in_proc.insert(name.to_string());
        let taint = line
            .rsplit_once('(')
            .and_then(|(_, t)| t.strip_suffix(')'))
            .map(str::to_string)
            .or_else(|| rd(&format!("/sys/module/{name}/taint")).map(|t| t.trim().to_string()))
            .filter(|t| !t.is_empty());
        let mut d = Driver {
            name: name.to_string(),
            path: paths.get(&kmod_key(name)).map(|p| p.display().to_string()),
            loaded: true,
            taint,
            ..Default::default()
        };
        inspect(&mut d);
        drivers.push(d);
    }

    let mut in_sysfs = BTreeSet::new();
    if let Ok(dir) = std::fs::read_dir(root.join("sys/module")) {
        for e in dir.flatten() {
            // Built-in modules have a kobject but no initstate.
            if e.path().join("initstate").exists() {
                in_sysfs.insert(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    let hidden_from_proc = in_sysfs.difference(&in_proc).cloned().collect();
    let hidden_from_sysfs = if in_sysfs.is_empty() {
        Vec::new()
    } else {
        in_proc.difference(&in_sysfs).cloned().collect()
    };
    LinuxView {
        drivers,
        hidden_from_proc,
        hidden_from_sysfs,
        modules_dir,
    }
}

#[cfg(windows)]
pub fn windows_loaded() -> anyhow::Result<Vec<Driver>> {
    use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
    const SYSTEM_MODULE_INFORMATION: i32 = 11;
    const ENTRY: usize = 296; // RTL_PROCESS_MODULE_INFORMATION on 64-bit

    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let mut ret = 0u32;
        // SAFETY: buf is writable for its full length.
        let st = unsafe {
            NtQuerySystemInformation(
                SYSTEM_MODULE_INFORMATION,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut ret,
            )
        };
        if st >= 0 {
            break;
        }
        if buf.len() >= 64 * 1024 * 1024 {
            anyhow::bail!(
                "NtQuerySystemInformation(SystemModuleInformation) failed: 0x{:x}",
                st as u32
            );
        }
        buf.resize((ret as usize).max(buf.len() * 2), 0);
    }
    let n = u32::from_le_bytes(buf[..4].try_into()?) as usize;
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let e = 8 + i * ENTRY;
        let Some(rec) = buf.get(e..e + ENTRY) else {
            break;
        };
        let name_off = u16::from_le_bytes([rec[38], rec[39]]) as usize;
        let full = &rec[40..296];
        let len = full.iter().position(|c| *c == 0).unwrap_or(full.len());
        let raw = String::from_utf8_lossy(&full[..len]).into_owned();
        let path = normalize_nt_path(&raw, &sysroot);
        let name = raw.get(name_off..).unwrap_or(&raw).to_string();
        let mut d = Driver {
            name,
            path: Some(path),
            loaded: true,
            ..Default::default()
        };
        inspect(&mut d);
        out.push(d);
    }
    Ok(out)
}

/// Map kernel-style image paths to Win32 paths.
#[cfg(any(windows, test))]
pub fn normalize_nt_path(raw: &str, sysroot: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\systemroot\") {
        return format!(r"{sysroot}\{}", &raw[raw.len() - rest.len()..]);
    }
    if let Some(rest) = raw.strip_prefix(r"\??\") {
        return rest.to_string();
    }
    if lower.starts_with(r"\windows\") {
        let drive = sysroot.get(..2).unwrap_or("C:");
        return format!("{drive}{raw}");
    }
    if lower.starts_with(r"system32\") {
        return format!(r"{sysroot}\{raw}");
    }
    raw.to_string()
}

const DRIVER_EXTS: &[&str] = &[".sys", ".ko", ".ko.xz", ".ko.zst", ".ko.gz"];

pub fn scan_paths(paths: &[PathBuf], all_pe: bool) -> Vec<Driver> {
    let mut out = Vec::new();
    for root in paths {
        for e in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if !e.file_type().is_file() {
                continue;
            }
            let p = e.path().display().to_string();
            let lp = p.to_ascii_lowercase();
            let explicit = e.depth() == 0;
            if !explicit && !all_pe && !DRIVER_EXTS.iter().any(|x| lp.ends_with(x)) {
                continue;
            }
            let mut d = Driver {
                name: e.file_name().to_string_lossy().into_owned(),
                path: Some(p),
                ..Default::default()
            };
            inspect(&mut d);
            if d.pe.is_some() || d.kmod_sig.is_some() || explicit {
                out.push(d);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_paths() {
        let r = r"C:\Windows";
        assert_eq!(
            normalize_nt_path(r"\SystemRoot\system32\drivers\acpi.sys", r),
            r"C:\Windows\system32\drivers\acpi.sys"
        );
        assert_eq!(
            normalize_nt_path(r"\??\C:\Tools\x.sys", r),
            r"C:\Tools\x.sys"
        );
        assert_eq!(
            normalize_nt_path(r"\Windows\System32\ntoskrnl.exe", r),
            r"C:\Windows\System32\ntoskrnl.exe"
        );
        assert_eq!(
            normalize_nt_path(r"System32\DRIVERS\a.sys", r),
            r"C:\Windows\System32\DRIVERS\a.sys"
        );
    }

    #[test]
    fn kmod_keys() {
        assert_eq!(kmod_key("kernel/drivers/net/e1000-e.ko.zst"), "e1000_e");
        assert_eq!(kmod_key("nvidia"), "nvidia");
    }

    fn signed_ko() -> Vec<u8> {
        let mut ko = b"\x7fELF fake module body".to_vec();
        // Fake CMS: issuer CN "Build key", sha256 digest OID.
        let mut cms = vec![0x30, 0x10];
        cms.extend_from_slice(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ]);
        cms.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 9]);
        cms.extend_from_slice(b"Build key");
        let len = cms.len() as u32;
        ko.extend(cms);
        ko.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0]);
        ko.extend_from_slice(&len.to_be_bytes());
        ko.extend_from_slice(KMOD_MAGIC);
        ko
    }

    #[test]
    fn kmod_signature_plain_and_gz() {
        let ko = signed_ko();
        let s = kmod_signature("m.ko", &ko);
        assert!(s.signed);
        assert_eq!(s.signer.as_deref(), Some("Build key"));
        assert_eq!(s.hash_algo, Some("sha256"));

        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            e.write_all(&ko).unwrap();
            e.finish().unwrap();
        }
        assert!(kmod_signature("m.ko.gz", &gz).signed);
        assert!(!kmod_signature("m.ko", b"\x7fELF unsigned").signed);
    }

    #[test]
    fn linux_cross_view_detects_hidden_module() {
        let root = std::env::temp_dir().join(format!("drvaudit-fx-{}", std::process::id()));
        let w = |p: &str, v: &str| {
            let f = root.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, v).unwrap();
        };
        w(
            "proc/modules",
            "visible 16384 0 - Live 0x0000000000000000\noot 4096 0 - Live 0x0 (OE)\n",
        );
        w("sys/module/visible/initstate", "live\n");
        w("sys/module/oot/initstate", "live\n");
        w("sys/module/sneaky/initstate", "live\n");
        std::fs::create_dir_all(root.join("sys/module/builtin_thing/parameters")).unwrap();
        let v = linux_loaded(&root);
        assert_eq!(v.hidden_from_proc, vec!["sneaky".to_string()]);
        assert!(v.hidden_from_sysfs.is_empty());
        assert_eq!(
            v.drivers
                .iter()
                .find(|d| d.name == "oot")
                .unwrap()
                .taint
                .as_deref(),
            Some("OE")
        );
        std::fs::remove_dir_all(root).ok();
    }
}
