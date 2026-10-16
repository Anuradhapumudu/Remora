//! Process CPU and memory measurement via macOS's own tools (`ps`, `footprint`),
//! so the numbers match what Activity Monitor shows and need no `unsafe` code.

use std::cmp::Reverse;
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::Duration;

/// Parses `ps` cputime: `[[dd-]hh:]mm:ss.ss`.
pub(crate) fn parse_cputime(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, s),
    };
    let mut secs = 0.0f64;
    for part in rest.split(':') {
        secs = secs * 60.0 + part.parse::<f64>().ok()?;
    }
    (secs.is_finite() && secs >= 0.0)
        .then(|| Duration::from_secs_f64(secs + days as f64 * 86_400.0))
}

/// Snapshot of CPU time per process: pid → (command name, total CPU time).
pub(crate) type CpuSnapshot = HashMap<u32, (String, Duration)>;

/// CPU time of every process right now.
#[cfg(target_os = "macos")]
pub(crate) fn all_cputimes() -> CpuSnapshot {
    let Ok(out) = Command::new("/bin/ps")
        .args(["-axo", "pid=,cputime=,comm="])
        .output()
    else {
        return HashMap::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let pid = it.next()?.parse().ok()?;
            let cpu = parse_cputime(it.next()?)?;
            let comm = it.collect::<Vec<_>>().join(" ");
            let name = comm.rsplit('/').next().unwrap_or(&comm).to_owned();
            Some((pid, (name, cpu)))
        })
        .collect()
}

/// Per-process CPU time consumed between two snapshots, largest first.
pub(crate) fn cpu_deltas(
    before: &CpuSnapshot,
    after: &CpuSnapshot,
) -> Vec<(u32, String, Duration)> {
    let mut v: Vec<_> = after
        .iter()
        .map(|(pid, (name, t))| {
            let prev = before.get(pid).map_or(Duration::ZERO, |(_, p)| *p);
            (*pid, name.clone(), t.saturating_sub(prev))
        })
        .filter(|(_, _, d)| !d.is_zero())
        .collect();
    v.sort_by_key(|d| Reverse(d.2));
    v
}

/// macOS thermal pressure (`ProcessInfo.thermalState`): nominal / fair / serious /
/// critical. Unlike `pmset -g therm` it reports pressure before any warning level.
#[cfg(target_os = "macos")]
pub(crate) fn thermal_state() -> &'static str {
    use objc2_foundation::{NSProcessInfo, NSProcessInfoThermalState as T};
    match NSProcessInfo::processInfo().thermalState() {
        T::Nominal => "nominal",
        T::Fair => "fair",
        T::Serious => "serious",
        T::Critical => "critical",
        _ => "unknown",
    }
}

/// Prints machine state that can skew benchmarks (criteria §6b): thermal and
/// performance warnings, power source, Low Power Mode, uptime, load averages.
#[cfg(target_os = "macos")]
pub(crate) fn print_machine_state(when: &str) {
    let run = |cmd: &str, args: &[&str]| {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let therm = run("/usr/bin/pmset", &["-g", "therm"]);
    let warnings: Vec<&str> = therm
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let batt = run("/usr/bin/pmset", &["-g", "batt"]);
    let power = batt.lines().next().unwrap_or("").trim().to_owned();
    let charge = batt.lines().nth(1).unwrap_or("").trim().to_owned();
    let low_power = run("/usr/bin/pmset", &["-g"])
        .lines()
        .find(|l| l.trim_start().starts_with("lowpowermode"))
        .map(|l| l.split_whitespace().last().unwrap_or("?").to_owned())
        .unwrap_or_else(|| "?".to_owned());
    let load = run("/usr/sbin/sysctl", &["-n", "vm.loadavg"]);
    let uptime = run("/usr/bin/uptime", &[]);
    println!("machine state ({when}): thermal state {}", thermal_state());
    println!("  power: {power} | {charge} | low power mode: {low_power}");
    println!("  thermal/performance: {}", warnings.join(" / "));
    println!(
        "  load averages: {} | uptime: {}",
        load.trim(),
        uptime.trim()
    );
}

/// Parses the "Footprint: N KB|MB|GB" header line of `footprint -p <pid>`, in bytes.
pub(crate) fn parse_footprint(output: &str) -> Option<u64> {
    let after = output.split("Footprint:").nth(1)?;
    let mut it = after.split_whitespace();
    let value: f64 = it.next()?.parse().ok()?;
    let unit = match it.next()? {
        "B" => 1.0,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((value * unit) as u64)
}

/// Physical footprint (Activity Monitor's "Memory" column) of `pid`, in bytes.
#[cfg(target_os = "macos")]
pub(crate) fn footprint(pid: u32) -> Option<u64> {
    let out = Command::new("/usr/bin/footprint")
        .args(["-p", &pid.to_string()])
        .output()
        .ok()?;
    parse_footprint(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ps_cputime_formats() {
        assert_eq!(parse_cputime("0:00.02"), Some(Duration::from_millis(20)));
        assert_eq!(
            parse_cputime(" 1:02.50 "),
            Some(Duration::from_millis(62_500))
        );
        assert_eq!(parse_cputime("1:00:00.00"), Some(Duration::from_secs(3600)));
        assert_eq!(
            parse_cputime("2-01:00:00.00"),
            Some(Duration::from_secs(2 * 86_400 + 3600))
        );
        assert_eq!(parse_cputime("abc"), None);
        assert_eq!(parse_cputime(""), None);
    }

    #[test]
    fn parses_footprint_header() {
        let out = "======\nzsh [27904]: 64-bit    Footprint: 2992 KB (16384 bytes per page)\n====";
        assert_eq!(parse_footprint(out), Some(2992 * 1024));
        assert_eq!(parse_footprint("x Footprint: 1.5 MB (…)"), Some(1_572_864));
        assert_eq!(parse_footprint("no header"), None);
        assert_eq!(parse_footprint("Footprint: 12 parsecs"), None);
    }

    #[test]
    fn deltas_include_new_processes_and_sort_descending() {
        let before = HashMap::from([(1, ("a".into(), Duration::from_secs(1)))]);
        let after = HashMap::from([
            (1, ("a".into(), Duration::from_secs(3))),
            (2, ("b".into(), Duration::from_secs(5))),
            (3, ("c".into(), Duration::ZERO)),
        ]);
        let d = cpu_deltas(&before, &after);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0], (2, "b".into(), Duration::from_secs(5)));
        assert_eq!(d[1], (1, "a".into(), Duration::from_secs(2)));
    }
}
