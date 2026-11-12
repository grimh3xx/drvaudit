//! drvaudit — read-only kernel driver / module auditor.
//!
//! Enumerates loaded kernel drivers (Windows) or modules (Linux), or scans
//! driver files on disk, and checks each against LOLDrivers and Microsoft's
//! vulnerable driver blocklist by file hash *and* Authenticode hash. Adds
//! signature, location, taint and cross-view (hidden module) checks, plus
//! baseline drift. Detection only: drvaudit never loads, unloads, or modifies
//! a driver.

mod audit;
mod enumerate;
mod intel;
mod pe;
mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use anstream::println;
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use serde::Serialize;

use audit::{Os, Verdict};
use enumerate::Driver;
use report::{Finding, Severity};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "https://github.com/grimh3xx/drvaudit";

#[derive(Parser)]
#[command(
    name = "drvaudit",
    version,
    about = "Read-only kernel driver auditor: BYOVD / blocklist / signature / hidden-module checks"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    opts: Opts,
}

#[derive(Subcommand)]
enum Cmd {
    /// Audit drivers loaded in the running kernel (default)
    Loaded,
    /// Audit driver files on disk (.sys, .ko[.xz|.zst|.gz]); directories are walked
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Treat every PE file as a candidate, not just .sys
        #[arg(long)]
        all_pe: bool,
    },
    /// Download LOLDrivers + the Microsoft blocklist into the local cache
    Update,
}

#[derive(clap::Args)]
struct Opts {
    /// LOLDrivers drivers.json to use instead of the cache
    #[arg(long, global = true, value_name = "FILE")]
    loldrivers: Option<PathBuf>,
    /// Microsoft SiPolicy blocklist XML to use instead of the cache
    #[arg(long, global = true, value_name = "FILE")]
    blocklist: Option<PathBuf>,
    /// Compare against a baseline saved with --save-baseline
    #[arg(long, global = true, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Write the current driver set as a baseline
    #[arg(long, global = true, value_name = "FILE")]
    save_baseline: Option<PathBuf>,
    /// Linux: audit a tree rooted here (snapshot of /proc, /sys, /lib/modules)
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<PathBuf>,
    /// Print every driver, not only those with findings
    #[arg(long, short, global = true)]
    list: bool,
    #[arg(long, global = true, conflicts_with = "sarif")]
    json: bool,
    #[arg(long, global = true)]
    sarif: bool,
    #[arg(long, global = true, default_value = "low", value_name = "LVL")]
    min_severity: String,
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    driver: &'a Driver,
    verdict: &'a Verdict,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let o = &cli.opts;
    if o.no_color {
        anstream::ColorChoice::Never.write_global();
    }
    let Some(min) = Severity::parse(&o.min_severity) else {
        eprintln!("invalid --min-severity: {}", o.min_severity);
        return ExitCode::from(64);
    };

    if matches!(cli.cmd, Some(Cmd::Update)) {
        let dir = intel::cache_dir();
        println!("  updating threat intel in {}", dir.display());
        return match intel::update(&dir) {
            Ok(lines) => {
                for l in lines {
                    println!("  {} {l}", "✓".green());
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("update failed: {e:#}");
                ExitCode::from(70)
            }
        };
    }

    let (lol, ms, intel_errs) = intel::load(
        &intel::cache_dir(),
        o.loldrivers.as_deref(),
        o.blocklist.as_deref(),
    );

    let mut extra: Vec<Finding> = Vec::new();
    let (drivers, os, mode) = match &cli.cmd {
        Some(Cmd::Scan { paths, all_pe }) => {
            let d = enumerate::scan_paths(paths, *all_pe);
            let os = if d.iter().any(|d| d.pe.is_some()) {
                Os::Windows
            } else {
                Os::Linux
            };
            (d, os, "scan")
        }
        _ => match loaded(o, &mut extra) {
            Ok((d, os)) => (d, os, "loaded"),
            Err(e) => {
                eprintln!("enumeration failed: {e:#}");
                return ExitCode::from(70);
            }
        },
    };

    let judged: Vec<(Driver, Verdict)> = drivers
        .into_iter()
        .map(|d| {
            let v = audit::judge(&d, lol.as_ref(), ms.as_ref(), os);
            (d, v)
        })
        .collect();

    let mut findings = audit::findings(&judged, os);
    findings.extend(extra);
    if let Some(f) = audit::intel_missing(lol.is_some(), ms.is_some(), &intel_errs) {
        findings.push(f);
    }
    if let Some(p) = &o.baseline {
        match std::fs::read_to_string(p)
            .map_err(anyhow::Error::from)
            .and_then(|s| Ok(serde_json::from_str(&s)?))
        {
            Ok(base) => findings.extend(audit::diff(&base, &judged)),
            Err(e) => {
                eprintln!("baseline {}: {e:#}", p.display());
                return ExitCode::from(66);
            }
        }
    }
    if let Some(p) = &o.save_baseline {
        let b = audit::make_baseline(&judged, hostname());
        if let Err(e) = std::fs::write(p, serde_json::to_string_pretty(&b).expect("serializable")) {
            eprintln!("writing baseline {}: {e}", p.display());
            return ExitCode::from(73);
        }
    }
    let findings = report::filter_sort(findings, min);

    if o.json {
        let rows: Vec<Row> = judged
            .iter()
            .map(|(d, v)| Row {
                driver: d,
                verdict: v,
            })
            .collect();
        let v = serde_json::json!({
            "tool": "drvaudit",
            "version": VERSION,
            "mode": mode,
            "intel": {
                "loldrivers": lol.as_ref().map(|l| serde_json::json!({"drivers": l.len(), "hashes": l.hashes(), "source": l.source})),
                "ms_blocklist": ms.as_ref().map(|m| serde_json::json!({"version": m.version, "rules": m.rules(), "source": m.source})),
            },
            "drivers": rows,
            "findings": findings,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("serializable")
        );
    } else if o.sarif {
        let s = report::sarif("drvaudit", VERSION, REPO, "drivers", &findings);
        println!(
            "{}",
            serde_json::to_string_pretty(&s).expect("serializable")
        );
    } else {
        banner();
        report::section("scope");
        report::kv("mode", mode);
        report::kv("drivers", judged.len());
        report::kv(
            "LOLDrivers",
            lol.as_ref().map_or("not loaded".yellow().to_string(), |l| {
                format!("{} drivers · {} hashes", l.len(), l.hashes())
            }),
        );
        report::kv(
            "MS blocklist",
            ms.as_ref().map_or("not loaded".yellow().to_string(), |m| {
                format!(
                    "{} · {} rules",
                    m.version.as_deref().unwrap_or("?"),
                    m.rules()
                )
            }),
        );
        if let Some(p) = &o.save_baseline {
            report::kv("baseline saved", p.display());
        }
        render_drivers(&judged, &findings, o.list);
        report::print_findings(&findings);
        report::print_summary(&findings);
        println!();
    }
    ExitCode::from(report::worst(&findings))
}

#[cfg(windows)]
fn loaded(o: &Opts, extra: &mut Vec<Finding>) -> anyhow::Result<(Vec<Driver>, Os)> {
    if o.root.is_some() {
        return linux_loaded(o, extra);
    }
    Ok((enumerate::windows_loaded()?, Os::Windows))
}

#[cfg(not(windows))]
fn loaded(o: &Opts, extra: &mut Vec<Finding>) -> anyhow::Result<(Vec<Driver>, Os)> {
    linux_loaded(o, extra)
}

fn linux_loaded(o: &Opts, extra: &mut Vec<Finding>) -> anyhow::Result<(Vec<Driver>, Os)> {
    let root = o.root.clone().unwrap_or_else(|| PathBuf::from("/"));
    let v = enumerate::linux_loaded(&root);
    if v.drivers.is_empty() && !root.join("proc/modules").exists() {
        anyhow::bail!("{} has no proc/modules", root.display());
    }
    if v.modules_dir.is_none() && !v.drivers.is_empty() {
        extra.push(
            Finding::new("DRV-018", Severity::Info, "Module files not found for the running kernel")
                .detail("/lib/modules/<release>/modules.dep is missing, so modules cannot be hashed or signature-checked (common in WSL and minimal containers)."),
        );
    }
    extra.extend(audit::cross_view(&v.hidden_from_proc, &v.hidden_from_sysfs));
    Ok((v.drivers, Os::Linux))
}

fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().or_else(|| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|s| s.trim().to_string())
    })
}

fn banner() {
    println!();
    println!(
        "  {}{}  {}",
        "drv".bold().cyan(),
        "audit".bold().bright_blue(),
        format!("v{VERSION}").dimmed()
    );
    println!(
        "  {}",
        "kernel driver auditor · BYOVD / blocklist / hidden modules · read-only".dimmed()
    );
}

fn render_drivers(drivers: &[(Driver, Verdict)], findings: &[Finding], all: bool) {
    report::section("drivers");
    let flagged = |d: &Driver| {
        let l = d.path.as_deref().unwrap_or(&d.name);
        findings
            .iter()
            .any(|f| f.source.as_deref() == Some(l) && f.severity >= Severity::Low)
    };
    let mut shown = 0;
    for (d, v) in drivers {
        if !all && !flagged(d) {
            continue;
        }
        shown += 1;
        let sig = match (&d.pe, &d.kmod_sig) {
            (Some(p), _) if p.signed => p
                .signer
                .clone()
                .unwrap_or_else(|| "signed".into())
                .green()
                .to_string(),
            (Some(_), _) => "no embedded sig".yellow().to_string(),
            (_, Some(k)) if k.signed => k
                .signer
                .clone()
                .unwrap_or_else(|| "signed".into())
                .green()
                .to_string(),
            (_, Some(_)) => "unsigned".red().to_string(),
            _ if !d.on_disk => "file missing".dimmed().to_string(),
            _ => "—".dimmed().to_string(),
        };
        let mark = if v.loldrivers.is_some() || v.ms_blocklist.is_some() {
            "✗".red().bold().to_string()
        } else if flagged(d) {
            "!".yellow().to_string()
        } else {
            "·".dimmed().to_string()
        };
        let ver =
            d.pe.as_ref()
                .and_then(|p| p.file_version.clone())
                .unwrap_or_default();
        println!("    {mark} {:<28} {:<16} {}", d.name, ver.dimmed(), sig);
        if let Some(p) = &d.path {
            println!("        {}", p.dimmed());
        }
    }
    if shown == 0 {
        println!(
            "    {} {}",
            "✓".green(),
            "no driver-level findings (use --list to show all)".dimmed()
        );
    }
}
