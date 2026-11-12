//! Minimal, bounds-checked PE reader for driver triage: Authenticode
//! ("authentihash") digests, embedded signature + signer, and the version
//! resource (OriginalFilename / FileVersion) that blocklist rules key on.

use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default, Serialize)]
pub struct PeInfo {
    pub machine: String,
    pub timestamp: u32,
    pub auth_sha1: String,
    pub auth_sha256: String,
    pub signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// SHA-1/256/384 of every certificate's TBSCertificate in the signature,
    /// which is what App Control `CertRoot Type="TBS"` rules reference.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chain_tbs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

struct Section {
    va: u32,
    vsize: u32,
    raw: u32,
    rsize: u32,
}

pub fn is_pe(b: &[u8]) -> bool {
    b.starts_with(b"MZ")
        && u32_at(b, 0x3c).is_some_and(|o| b.get(o as usize..o as usize + 4) == Some(b"PE\0\0"))
}

pub fn parse(b: &[u8]) -> Option<PeInfo> {
    if !is_pe(b) {
        return None;
    }
    let pe = u32_at(b, 0x3c)? as usize;
    let coff = pe + 4;
    let machine = u16_at(b, coff)?;
    let nsec = u16_at(b, coff + 2)? as usize;
    let timestamp = u32_at(b, coff + 4)?;
    let opt_size = u16_at(b, coff + 16)? as usize;
    let opt = coff + 20;
    let magic = u16_at(b, opt)?;
    let dd = match magic {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    let checksum_off = opt + 64;
    let secdir_off = dd + 4 * 8;
    if secdir_off + 8 > b.len() {
        return None;
    }
    let cert_off = u32_at(b, secdir_off)? as usize;
    let cert_len = u32_at(b, secdir_off + 4)? as usize;
    let has_cert = cert_off != 0
        && cert_len != 0
        && cert_off.checked_add(cert_len).is_some_and(|e| e <= b.len());
    let end = if has_cert { cert_off } else { b.len() };
    if end < secdir_off + 8 {
        return None;
    }

    // Authenticode digest: the image minus CheckSum, the security directory
    // entry and the attribute certificate table.
    let ranges = [
        (0, checksum_off),
        (checksum_off + 4, secdir_off),
        (secdir_off + 8, end),
    ];
    let mut s1 = Sha1::new();
    let mut s256 = Sha256::new();
    for (a, z) in ranges {
        s1.update(&b[a..z]);
        s256.update(&b[a..z]);
    }

    let sec_tab = opt + opt_size;
    let sections: Vec<Section> = (0..nsec)
        .filter_map(|i| {
            let s = sec_tab + i * 40;
            Some(Section {
                vsize: u32_at(b, s + 8)?,
                va: u32_at(b, s + 12)?,
                rsize: u32_at(b, s + 16)?,
                raw: u32_at(b, s + 20)?,
            })
        })
        .collect();

    let mut info = PeInfo {
        machine: match machine {
            0x14c => "x86",
            0x8664 => "x64",
            0xaa64 => "arm64",
            0x1c4 => "arm",
            _ => "other",
        }
        .into(),
        timestamp,
        auth_sha1: hex::encode(s1.finalize()),
        auth_sha256: hex::encode(s256.finalize()),
        signed: has_cert,
        ..Default::default()
    };

    if has_cert {
        // WIN_CERTIFICATE header is 8 bytes; the PKCS#7 blob follows.
        if let Some(sig) = signer_of(&b[cert_off + 8.min(cert_len)..cert_off + cert_len]) {
            info.signer = sig.signer;
            info.issuer = sig.issuer;
            info.chain_tbs = sig.tbs;
        }
    }

    let rva_to_off = |rva: u32| -> Option<usize> {
        sections.iter().find_map(|s| {
            let span = s.vsize.max(s.rsize);
            (rva >= s.va && rva < s.va.checked_add(span)?).then(|| (rva - s.va + s.raw) as usize)
        })
    };
    let rsrc_rva = u32_at(b, dd + 2 * 8)?;
    if rsrc_rva != 0 {
        if let Some(base) = rva_to_off(rsrc_rva) {
            if let Some((data_rva, size)) = find_version_resource(b, base) {
                if let Some(off) = rva_to_off(data_rva) {
                    if let Some(vi) = b.get(off..off + size as usize) {
                        apply_version(vi, &mut info);
                    }
                }
            }
        }
    }
    Some(info)
}

struct SigInfo {
    signer: Option<String>,
    issuer: Option<String>,
    tbs: Vec<String>,
}

/// Signer = the certificate in the PKCS#7 bag that issued no other cert there.
fn signer_of(pkcs7: &[u8]) -> Option<SigInfo> {
    use sha2::Sha384;
    use x509_parser::prelude::*;
    let mut certs = Vec::new();
    let mut tbs = Vec::new();
    let mut i = 0;
    while i + 4 < pkcs7.len() && certs.len() < 16 {
        if pkcs7[i] == 0x30 && pkcs7[i + 1] == 0x82 {
            let len = u16::from_be_bytes([pkcs7[i + 2], pkcs7[i + 3]]) as usize + 4;
            if let Some(der) = pkcs7.get(i..i + len) {
                if let Ok((_, c)) = X509Certificate::from_der(der) {
                    let cn = |n: &X509Name| {
                        n.iter_common_name()
                            .next()
                            .and_then(|a| a.as_str().ok())
                            .map(str::to_string)
                            .unwrap_or_else(|| n.to_string())
                    };
                    let raw = c.tbs_certificate.as_ref();
                    tbs.push(hex::encode(Sha1::digest(raw)));
                    tbs.push(hex::encode(Sha256::digest(raw)));
                    tbs.push(hex::encode(Sha384::digest(raw)));
                    certs.push((
                        cn(c.subject()),
                        cn(c.issuer()),
                        c.subject().to_string(),
                        c.issuer().to_string(),
                    ));
                    i += len;
                    continue;
                }
            }
        }
        i += 1;
    }
    if certs.is_empty() {
        return None;
    }
    let leaf = certs.iter().find(|(_, _, subj, _)| {
        !certs
            .iter()
            .any(|(_, _, s2, iss2)| iss2 == subj && s2 != subj)
    });
    Some(SigInfo {
        signer: leaf.map(|l| l.0.clone()),
        issuer: leaf.map(|l| l.1.clone()),
        tbs,
    })
}

const RT_VERSION: u32 = 16;

fn find_version_resource(b: &[u8], base: usize) -> Option<(u32, u32)> {
    // Type -> Name -> Language -> IMAGE_RESOURCE_DATA_ENTRY
    let entries = |dir: usize| -> Option<Vec<(u32, u32)>> {
        let named = u16_at(b, dir + 12)? as usize;
        let ids = u16_at(b, dir + 14)? as usize;
        (0..(named + ids).min(512))
            .map(|i| Some((u32_at(b, dir + 16 + i * 8)?, u32_at(b, dir + 20 + i * 8)?)))
            .collect()
    };
    let (_, t) = entries(base)?
        .into_iter()
        .find(|(name, _)| *name == RT_VERSION)?;
    let mut node = t;
    for _ in 0..2 {
        if node & 0x8000_0000 == 0 {
            return None;
        }
        let dir = base + (node & 0x7fff_ffff) as usize;
        node = entries(dir)?.first()?.1;
    }
    if node & 0x8000_0000 != 0 {
        return None;
    }
    let de = base + node as usize;
    Some((u32_at(b, de)?, u32_at(b, de + 4)?))
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

/// (wLength, wValueLength, wType, key, value offset) of a VS_VERSIONINFO-style node.
fn vnode(b: &[u8], off: usize) -> Option<(usize, usize, u16, String, usize)> {
    let len = u16_at(b, off)? as usize;
    let vlen = u16_at(b, off + 2)? as usize;
    let typ = u16_at(b, off + 4)?;
    let mut p = off + 6;
    let mut key = Vec::new();
    loop {
        let c = u16_at(b, p)?;
        p += 2;
        if c == 0 {
            break;
        }
        key.push(c);
        if key.len() > 64 {
            return None;
        }
    }
    Some((len, vlen, typ, String::from_utf16_lossy(&key), align4(p)))
}

fn utf16z(b: &[u8], off: usize, max_chars: usize) -> String {
    let v: Vec<u16> = (0..max_chars)
        .map_while(|i| u16_at(b, off + i * 2).filter(|c| *c != 0))
        .collect();
    String::from_utf16_lossy(&v).trim().to_string()
}

fn apply_version(vi: &[u8], info: &mut PeInfo) {
    let Some((len, vlen, _, key, voff)) = vnode(vi, 0) else {
        return;
    };
    if key != "VS_VERSION_INFO" || len > vi.len() {
        return;
    }
    if vlen >= 52 && u32_at(vi, voff) == Some(0xFEEF_04BD) {
        let ms = u32_at(vi, voff + 8).unwrap_or(0);
        let ls = u32_at(vi, voff + 12).unwrap_or(0);
        info.file_version = Some(format!(
            "{}.{}.{}.{}",
            ms >> 16,
            ms & 0xffff,
            ls >> 16,
            ls & 0xffff
        ));
    }
    // Walk StringFileInfo -> StringTable -> String.
    let mut p = align4(voff + vlen);
    while p + 6 < len {
        let Some((clen, _, _, ckey, cval)) = vnode(vi, p) else {
            break;
        };
        if clen == 0 {
            break;
        }
        if ckey == "StringFileInfo" {
            let mut t = cval;
            while t + 6 < p + clen {
                let Some((tlen, _, _, _, tval)) = vnode(vi, t) else {
                    break;
                };
                if tlen == 0 {
                    break;
                }
                let mut s = tval;
                while s + 6 < t + tlen {
                    let Some((slen, svlen, _, skey, sval)) = vnode(vi, s) else {
                        break;
                    };
                    if slen == 0 {
                        break;
                    }
                    let value = utf16z(vi, sval, svlen.min(260));
                    let slot = match skey.as_str() {
                        "OriginalFilename" => Some(&mut info.original_filename),
                        "CompanyName" => Some(&mut info.company),
                        "FileDescription" => Some(&mut info.description),
                        _ => None,
                    };
                    if let Some(slot) = slot {
                        if slot.is_none() && !value.is_empty() {
                            *slot = Some(value);
                        }
                    }
                    s = align4(s + slen);
                }
                t = align4(t + tlen);
            }
        }
        p = align4(p + clen);
    }
}

/// Compare dotted versions numerically ("10.0.2" < "10.0.10").
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| p.trim().parse().unwrap_or(0))
            .collect()
    };
    let (mut x, mut y) = (parse(a), parse(b));
    let n = x.len().max(y.len());
    x.resize(n, 0);
    y.resize(n, 0);
    x.cmp(&y)
}

#[cfg(test)]
pub mod build {
    //! Tiny synthetic PE32+ image for tests.
    pub fn minimal_pe(cert: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x80;
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        b[0x98 + 64..0x98 + 68].copy_from_slice(&0xdeadbeefu32.to_le_bytes()); // CheckSum
        for (i, x) in b.iter_mut().enumerate().skip(0x200) {
            *x = (i % 251) as u8;
        }
        if let Some(c) = cert {
            let off = b.len() as u32;
            let secdir = 0x98 + 112 + 32;
            b[secdir..secdir + 4].copy_from_slice(&off.to_le_bytes());
            b[secdir + 4..secdir + 8].copy_from_slice(&((c.len() + 8) as u32).to_le_bytes());
            b.extend_from_slice(&((c.len() + 8) as u32).to_le_bytes());
            b.extend_from_slice(&[0, 2, 2, 0]);
            b.extend_from_slice(c);
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::build::minimal_pe;
    use super::*;

    #[test]
    fn authentihash_ignores_checksum_and_signature() {
        let a = parse(&minimal_pe(None)).unwrap();
        let mut patched = minimal_pe(None);
        patched[0x98 + 64] ^= 0xff; // CheckSum is excluded
        let b = parse(&patched).unwrap();
        assert_eq!(a.auth_sha256, b.auth_sha256);
        assert!(!a.signed);

        let signed = parse(&minimal_pe(Some(&[0x55; 64]))).unwrap();
        assert!(signed.signed);
        // Appending a certificate table must not change the authentihash.
        assert_eq!(signed.auth_sha256, a.auth_sha256);
        assert_eq!(signed.auth_sha1, a.auth_sha1);
    }

    #[test]
    fn content_change_changes_hash() {
        let a = parse(&minimal_pe(None)).unwrap();
        let mut m = minimal_pe(None);
        m[0x300] ^= 1;
        assert_ne!(a.auth_sha256, parse(&m).unwrap().auth_sha256);
    }

    #[test]
    fn rejects_non_pe() {
        assert!(parse(b"\x7fELF....").is_none());
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn version_compare() {
        use std::cmp::Ordering::*;
        assert_eq!(version_cmp("10.0.2", "10.0.10"), Less);
        assert_eq!(version_cmp("1.2", "1.2.0.0"), Equal);
        assert_eq!(version_cmp("3", "2.99"), Greater);
    }

    #[test]
    fn parses_version_info_node() {
        // VS_VERSION_INFO with fixed info and one String "OriginalFilename"="x.sys".
        fn wstr(s: &str) -> Vec<u8> {
            s.encode_utf16()
                .chain(Some(0))
                .flat_map(|c| c.to_le_bytes())
                .collect()
        }
        fn pad(v: &mut Vec<u8>) {
            while v.len() % 4 != 0 {
                v.push(0);
            }
        }
        fn node(key: &str, value: &[u8], vlen_units: usize, typ: u16, children: &[u8]) -> Vec<u8> {
            let mut v = vec![0u8; 6];
            v.extend(wstr(key));
            pad(&mut v);
            v.extend_from_slice(value);
            pad(&mut v);
            v.extend_from_slice(children);
            let len = v.len() as u16;
            v[0..2].copy_from_slice(&len.to_le_bytes());
            v[2..4].copy_from_slice(&(vlen_units as u16).to_le_bytes());
            v[4..6].copy_from_slice(&typ.to_le_bytes());
            v
        }
        let val = wstr("x.sys");
        let s = node("OriginalFilename", &val, val.len() / 2, 1, &[]);
        let table = node("040904b0", &[], 0, 1, &s);
        let sfi = node("StringFileInfo", &[], 0, 1, &table);
        let mut fixed = vec![0u8; 52];
        fixed[0..4].copy_from_slice(&0xFEEF04BDu32.to_le_bytes());
        fixed[8..12].copy_from_slice(&((10u32 << 16) | 2).to_le_bytes());
        fixed[12..16].copy_from_slice(&((300u32 << 16) | 7).to_le_bytes());
        let root = node("VS_VERSION_INFO", &fixed, 52, 0, &sfi);
        let mut info = PeInfo::default();
        apply_version(&root, &mut info);
        assert_eq!(info.file_version.as_deref(), Some("10.2.300.7"));
        assert_eq!(info.original_filename.as_deref(), Some("x.sys"));
    }
}
