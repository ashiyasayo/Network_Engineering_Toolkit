//! DPDK P0 環境探測；本 crate 尚不連結或初始化 DPDK EAL。

#![forbid(unsafe_code)]

mod environment;
mod planning;

pub use environment::{
    EnvironmentCollection, LinuxBenchmarkSnapshotRequest, RssEvidence,
    collect_benchmark_environment, detect_management_pci_address, parse_rss_evidence,
    resolve_management_pci_from_route,
};
pub use planning::{
    DataPlaneCpu, MbufPoolSizing, NicQueueCapacity, QueuePlan, QueueSelection, RxQueueAssignment,
    plan_queues, required_mbufs,
};

/// 此 build 是否已實際連結 native DPDK C shim。
#[must_use]
pub const fn is_backend_built() -> bool {
    nettool_dpdk_safe::is_native_dpdk_built()
}

use nettool_domain::NicProbe;
use nettool_domain::{Platform, ProbeReport};
#[cfg(target_os = "linux")]
use nettool_error::ErrorCode;
use nettool_error::NetToolError;
#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(not(target_os = "linux"))]
use std::process::Command;

/// Preflight check 的嚴重程度。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightSeverity {
    /// 條件已滿足。
    Pass,
    /// 一般模式可繼續，但結果會 degraded/not-certifiable。
    Warn,
    /// 不得執行此模式。
    Fail,
}

/// 單一 DPDK preflight check。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightCheck {
    /// Stable check ID。
    pub id: &'static str,
    /// Check 結果。
    pub severity: PreflightSeverity,
    /// 可呈現給 CLI/GUI 的原因。
    pub message: String,
}

/// DPDK session 所需的硬體條件。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpdkPreflightRequest {
    /// 目標 NIC PCI address。
    pub pci_address: String,
    /// 已由 control plane 證明的 management NIC PCI address；相同目標一律拒絕。
    pub management_pci_address: Option<String>,
    /// 需要的 RX queues。
    pub rx_queues: u32,
    /// 需要的 TX queues。
    pub tx_queues: u32,
    /// Worker 所在 NUMA node。
    pub worker_numa_node: Option<i32>,
    /// Pinned logical CPUs。
    pub worker_cpus: Vec<u32>,
    /// 最低空閒 Huge Pages 數量。
    pub required_huge_pages: u64,
    /// 是否為 100G certification run。
    pub certification_mode: bool,
}

/// 完整 DPDK preflight 結果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpdkPreflightReport {
    /// 一般 session 是否可啟動。
    pub can_run: bool,
    /// 是否可標記 100G certified。
    pub certifiable: bool,
    /// 所有 gates，不省略 warning/pass evidence。
    pub checks: Vec<PreflightCheck>,
}

/// `AF_XDP` session 所需的介面與 queue 條件。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AfXdpPreflightRequest {
    /// 目標 Linux netdev name。
    pub interface_name: String,
    /// 要綁定的 RX/TX queue。
    pub queue_id: u32,
    /// 是否強制要求 kernel zero-copy。
    pub require_zero_copy: bool,
}

/// `AF_XDP` preflight 結果；不建立 socket，也不把 capability 當成 implementation。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AfXdpPreflightReport {
    /// 是否可進入 backend setup。
    pub can_run: bool,
    /// 是否滿足 zero-copy 強制條件。
    pub zero_copy_ready: bool,
    /// 所有檢查證據。
    pub checks: Vec<PreflightCheck>,
}

/// 依最新 capability snapshot 驗證 `AF_XDP` interface/queue/zero-copy gates。
///
/// Zero-copy 被要求時，缺少 driver evidence 會直接 fail，禁止靜默退回 copy mode。
#[must_use]
pub fn evaluate_af_xdp_preflight(
    report: &ProbeReport,
    request: &AfXdpPreflightRequest,
) -> AfXdpPreflightReport {
    let mut checks = Vec::new();
    let linux = report.platform == Platform::Linux;
    checks.push(check(
        "AF_XDP_PLATFORM",
        if linux {
            PreflightSeverity::Pass
        } else {
            PreflightSeverity::Fail
        },
        if linux {
            "AF_XDP requires Linux"
        } else {
            "AF_XDP is unavailable on this platform"
        },
    ));
    checks.push(check(
        "AF_XDP_SURFACE",
        if report.af_xdp_capable {
            PreflightSeverity::Pass
        } else {
            PreflightSeverity::Fail
        },
        if report.af_xdp_capable {
            "Linux BPF/AF_XDP surface is available"
        } else {
            "Linux BPF/AF_XDP surface is unavailable"
        },
    ));
    let nic = report
        .nics
        .iter()
        .find(|nic| nic.name == request.interface_name);
    checks.push(check(
        "AF_XDP_INTERFACE",
        if nic.is_some() {
            PreflightSeverity::Pass
        } else {
            PreflightSeverity::Fail
        },
        if nic.is_some() {
            "target interface was discovered"
        } else {
            "target interface was not discovered"
        },
    ));
    let queue_ok = nic
        .and_then(|nic| nic.rx_queues.zip(nic.tx_queues))
        .is_some_and(|(rx, tx)| request.queue_id < rx && request.queue_id < tx);
    checks.push(check(
        "AF_XDP_QUEUE",
        if queue_ok {
            PreflightSeverity::Pass
        } else {
            PreflightSeverity::Fail
        },
        if queue_ok {
            "requested AF_XDP queue is available"
        } else {
            "requested AF_XDP queue is unavailable"
        },
    ));
    let zero_copy_ready = report.af_xdp_zero_copy_capable;
    checks.push(check(
        "AF_XDP_ZERO_COPY",
        if zero_copy_ready {
            PreflightSeverity::Pass
        } else if request.require_zero_copy {
            PreflightSeverity::Fail
        } else {
            PreflightSeverity::Warn
        },
        if zero_copy_ready {
            "AF_XDP zero-copy driver evidence is available"
        } else if request.require_zero_copy {
            "AF_XDP zero-copy was required but not proven"
        } else {
            "AF_XDP zero-copy is not proven; compatibility mode only"
        },
    ));
    let can_run = checks
        .iter()
        .all(|check| check.severity != PreflightSeverity::Fail);
    AfXdpPreflightReport {
        can_run,
        zero_copy_ready,
        checks,
    }
}

/// 依最新 capability snapshot 評估 DPDK session，不永久快取結果。
///
/// 這裡刻意維持單一線性 gate 清單，讓每個規格 gate 的順序與嚴重度可直接稽核。
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn evaluate_preflight(
    report: &ProbeReport,
    request: &DpdkPreflightRequest,
) -> DpdkPreflightReport {
    let mut checks = Vec::new();
    checks.push(check(
        "DPDK_RUNTIME",
        if report.dpdk_capable {
            PreflightSeverity::Pass
        } else {
            PreflightSeverity::Fail
        },
        if report.dpdk_capable {
            "DPDK runtime is available"
        } else {
            "DPDK runtime is unavailable"
        },
    ));
    let nic = report
        .nics
        .iter()
        .find(|nic| nic.pci_address.as_deref() == Some(request.pci_address.as_str()));
    checks.push(check(
        "PCI_DEVICE",
        if nic.is_some() {
            PreflightSeverity::Pass
        } else {
            PreflightSeverity::Fail
        },
        if nic.is_some() {
            "PCI device was discovered"
        } else {
            "PCI device was not discovered"
        },
    ));
    if let Some(management_pci) = request.management_pci_address.as_deref() {
        let protected = management_pci != request.pci_address;
        checks.push(check(
            "MANAGEMENT_NIC_PROTECTION",
            if protected {
                PreflightSeverity::Pass
            } else {
                PreflightSeverity::Fail
            },
            if protected {
                "target NIC is distinct from the management NIC"
            } else {
                "target NIC carries the management control plane"
            },
        ));
    }
    if let Some(nic) = nic {
        let queue_ok = nic
            .rx_queues
            .is_some_and(|queues| queues >= request.rx_queues)
            && nic
                .tx_queues
                .is_some_and(|queues| queues >= request.tx_queues)
            && request.rx_queues > 0
            && request.tx_queues > 0;
        checks.push(check(
            "QUEUE_CAPACITY",
            if queue_ok {
                PreflightSeverity::Pass
            } else {
                PreflightSeverity::Fail
            },
            if queue_ok {
                "requested RX/TX queues are available"
            } else {
                "requested RX/TX queues exceed detected capacity or are zero"
            },
        ));
        let driver_ready = nic
            .driver
            .as_deref()
            .is_some_and(|driver| matches!(driver, "vfio-pci" | "uio_pci_generic" | "igb_uio"));
        checks.push(check(
            "DRIVER_STATE",
            if driver_ready {
                PreflightSeverity::Pass
            } else {
                degraded(request.certification_mode)
            },
            if driver_ready {
                "NIC is bound to a supported userspace driver"
            } else {
                "NIC is not bound to a known DPDK userspace driver"
            },
        ));
        let numa_match = request
            .worker_numa_node
            .zip(nic.numa_node)
            .is_none_or(|(worker, device)| worker == device || device < 0);
        checks.push(check(
            "NUMA_LOCALITY",
            if numa_match {
                PreflightSeverity::Pass
            } else {
                degraded(request.certification_mode)
            },
            if numa_match {
                "worker and NIC NUMA locality is compatible"
            } else {
                "worker and NIC are on different NUMA nodes"
            },
        ));
    }
    let huge_pages_ok = report
        .huge_pages_free
        .is_some_and(|pages| pages >= request.required_huge_pages)
        && request.required_huge_pages > 0;
    checks.push(check(
        "HUGE_PAGES",
        if huge_pages_ok {
            PreflightSeverity::Pass
        } else {
            degraded(request.certification_mode)
        },
        if huge_pages_ok {
            "required Huge Pages are available"
        } else {
            "required Huge Pages are missing"
        },
    ));
    let cpus_unique = !request.worker_cpus.is_empty() && {
        let mut cpus = request.worker_cpus.clone();
        cpus.sort_unstable();
        cpus.dedup();
        cpus.len() == request.worker_cpus.len()
            && request
                .worker_cpus
                .iter()
                .all(|cpu| (*cpu as usize) < report.logical_cpus)
    };
    checks.push(check(
        "CPU_AFFINITY",
        if cpus_unique {
            PreflightSeverity::Pass
        } else {
            PreflightSeverity::Fail
        },
        if cpus_unique {
            "worker CPU mapping is valid"
        } else {
            "worker CPU mapping is empty, duplicated, or out of range"
        },
    ));
    let has_failure = checks
        .iter()
        .any(|item| item.severity == PreflightSeverity::Fail);
    let has_warning = checks
        .iter()
        .any(|item| item.severity == PreflightSeverity::Warn);
    DpdkPreflightReport {
        can_run: !has_failure,
        certifiable: !has_failure && !has_warning,
        checks,
    }
}

const fn degraded(certification_mode: bool) -> PreflightSeverity {
    if certification_mode {
        PreflightSeverity::Fail
    } else {
        PreflightSeverity::Warn
    }
}

fn check(id: &'static str, severity: PreflightSeverity, message: &str) -> PreflightCheck {
    PreflightCheck {
        id,
        severity,
        message: message.to_owned(),
    }
}

/// 探測目前主機可供資料平面使用的硬體與核心能力。
///
/// # Errors
///
/// Linux 上若無法讀取網路介面的 sysfs 根目錄，回傳
/// [`NetToolError`]；個別介面或選用資訊讀取失敗則降級為警告或未知值。
pub fn probe_environment() -> Result<ProbeReport, NetToolError> {
    let platform = current_platform();
    let logical_cpus = std::thread::available_parallelism().map_or(1, usize::from);
    let mut warnings = Vec::new();

    #[cfg(target_os = "linux")]
    let (nics, numa_nodes, huge_pages_total, huge_pages_free, huge_page_size_kib) =
        probe_linux(&mut warnings)?;

    #[cfg(not(target_os = "linux"))]
    let (nics, numa_nodes, huge_pages_total, huge_pages_free, huge_page_size_kib) = {
        let nics = probe_platform_interfaces(&mut warnings);
        warnings.push(
            "Detailed DPDK NUMA/Huge Page probing is currently available on Linux only".to_owned(),
        );
        (nics, None, None, None, None)
    };

    let af_xdp_capable =
        cfg!(target_os = "linux") && Path::new("/sys/fs/bpf").is_dir() && !nics.is_empty();
    if af_xdp_capable {
        warnings.push(
            "AF_XDP core/BPF surface detected; zero-copy driver support remains unverified"
                .to_owned(),
        );
    }
    Ok(ProbeReport {
        schema_version: "1.0",
        platform,
        logical_cpus,
        numa_nodes,
        huge_pages_total,
        huge_pages_free,
        huge_page_size_kib,
        nics,
        dpdk_capable: detect_dpdk_runtime(),
        af_xdp_capable,
        af_xdp_zero_copy_capable: false,
        warnings,
    })
}

#[cfg(target_os = "macos")]
fn probe_platform_interfaces(warnings: &mut Vec<String>) -> Vec<NicProbe> {
    let output = match Command::new("/sbin/ifconfig").arg("-l").output() {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            warnings.push(format!("ifconfig failed with status {}", output.status));
            return Vec::new();
        }
        Err(error) => {
            warnings.push(format!("cannot start ifconfig: {error}"));
            return Vec::new();
        }
    };
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter(|name| !name.is_empty())
        .map(|name| NicProbe {
            name: name.to_owned(),
            pci_address: None,
            driver: None,
            link_speed_mbps: None,
            rx_queues: None,
            tx_queues: None,
            numa_node: None,
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn probe_platform_interfaces(warnings: &mut Vec<String>) -> Vec<NicProbe> {
    let output =
        match Command::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetAdapter | Select-Object -ExpandProperty Name",
            ])
            .output()
        {
            Ok(output) if output.status.success() => output,
            Ok(output) => {
                warnings.push(format!(
                    "PowerShell adapter query failed with status {}",
                    output.status
                ));
                return Vec::new();
            }
            Err(error) => {
                warnings.push(format!("cannot start PowerShell adapter query: {error}"));
                return Vec::new();
            }
        };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| NicProbe {
            name: name.to_owned(),
            pci_address: None,
            driver: None,
            link_speed_mbps: None,
            rx_queues: None,
            tx_queues: None,
            numa_node: None,
        })
        .collect()
}

const fn current_platform() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Unknown
    }
}

fn detect_dpdk_runtime() -> bool {
    [
        "/usr/lib/libdpdk.so",
        "/usr/local/lib/libdpdk.so",
        "/usr/lib/x86_64-linux-gnu/libdpdk.so",
        "/usr/local/lib/libdpdk.dylib",
    ]
    .iter()
    .any(|path| Path::new(path).exists())
}

#[cfg(target_os = "linux")]
type LinuxProbe = (
    Vec<NicProbe>,
    Option<u32>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
);

#[cfg(target_os = "linux")]
fn probe_linux(warnings: &mut Vec<String>) -> Result<LinuxProbe, NetToolError> {
    let net_root = Path::new("/sys/class/net");
    let entries = fs::read_dir(net_root).map_err(|error| {
        NetToolError::new(
            ErrorCode::ProbeFailed,
            format!("cannot read {}: {error}", net_root.display()),
            true,
        )
    })?;
    let mut nics = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => nics.push(probe_linux_nic(&entry.path())),
            Err(error) => warnings.push(format!("Network interface entry was skipped: {error}")),
        }
    }
    nics.sort_by(|left, right| left.name.cmp(&right.name));

    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_else(|error| {
        warnings.push(format!("Huge page information is unavailable: {error}"));
        String::new()
    });
    let nodes = fs::read_dir("/sys/devices/system/node")
        .ok()
        .and_then(|entries| {
            let count = entries
                .filter_map(Result::ok)
                .filter(|entry| is_numbered_name(&entry.file_name().to_string_lossy(), "node"))
                .count();
            u32::try_from(count).ok()
        });
    Ok((
        nics,
        nodes,
        meminfo_value(&meminfo, "HugePages_Total:"),
        meminfo_value(&meminfo, "HugePages_Free:"),
        meminfo_value(&meminfo, "Hugepagesize:"),
    ))
}

#[cfg(target_os = "linux")]
fn probe_linux_nic(path: &Path) -> NicProbe {
    let device = path.join("device");
    NicProbe {
        name: path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
        pci_address: fs::canonicalize(&device).ok().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
        driver: fs::read_link(device.join("driver")).ok().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
        link_speed_mbps: read_number(path.join("speed")),
        rx_queues: count_queues(path.join("queues"), "rx-"),
        tx_queues: count_queues(path.join("queues"), "tx-"),
        numa_node: read_text(device.join("numa_node")).and_then(|value| value.parse().ok()),
    }
}

#[cfg(target_os = "linux")]
fn read_text(path: PathBuf) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

#[cfg(target_os = "linux")]
fn read_number(path: PathBuf) -> Option<u64> {
    read_text(path).and_then(|value| value.parse().ok())
}

#[cfg(target_os = "linux")]
fn count_queues(path: PathBuf, prefix: &str) -> Option<u32> {
    fs::read_dir(path).ok().and_then(|entries| {
        let count = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .count();
        u32::try_from(count).ok()
    })
}

#[cfg(target_os = "linux")]
fn meminfo_value(contents: &str, key: &str) -> Option<u64> {
    contents
        .lines()
        .find(|line| line.starts_with(key))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
}

#[cfg(target_os = "linux")]
fn is_numbered_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{is_numbered_name, meminfo_value};

    #[test]
    fn parses_meminfo_values() {
        assert_eq!(
            meminfo_value("HugePages_Total:  16\n", "HugePages_Total:"),
            Some(16)
        );
    }

    #[test]
    fn accepts_only_numbered_sysfs_entries() {
        assert!(is_numbered_name("node12", "node"));
        assert!(!is_numbered_name("nodepossible", "node"));
    }
}

#[cfg(test)]
mod preflight_tests {
    use super::{
        AfXdpPreflightRequest, DpdkPreflightRequest, PreflightSeverity, evaluate_af_xdp_preflight,
        evaluate_preflight,
    };
    use nettool_domain::{NicProbe, Platform, ProbeReport};

    fn report() -> ProbeReport {
        ProbeReport {
            schema_version: "1.0",
            platform: Platform::Linux,
            logical_cpus: 16,
            numa_nodes: Some(2),
            huge_pages_total: Some(16),
            huge_pages_free: Some(8),
            huge_page_size_kib: Some(2048),
            nics: vec![NicProbe {
                name: "dpdk0".to_owned(),
                pci_address: Some("0000:01:00.0".to_owned()),
                driver: Some("vfio-pci".to_owned()),
                link_speed_mbps: Some(100_000),
                rx_queues: Some(8),
                tx_queues: Some(8),
                numa_node: Some(0),
            }],
            dpdk_capable: true,
            af_xdp_capable: true,
            af_xdp_zero_copy_capable: false,
            warnings: Vec::new(),
        }
    }

    fn request(certification_mode: bool) -> DpdkPreflightRequest {
        DpdkPreflightRequest {
            pci_address: "0000:01:00.0".to_owned(),
            management_pci_address: None,
            rx_queues: 4,
            tx_queues: 4,
            worker_numa_node: Some(0),
            worker_cpus: vec![2, 3, 4, 5],
            required_huge_pages: 4,
            certification_mode,
        }
    }

    #[test]
    fn valid_environment_is_certifiable() {
        let result = evaluate_preflight(&report(), &request(true));
        assert!(result.can_run);
        assert!(result.certifiable);
        assert!(
            result
                .checks
                .iter()
                .all(|check| check.severity == PreflightSeverity::Pass)
        );
    }

    #[test]
    fn wrong_numa_warns_normally_but_fails_certification() {
        let mut normal = request(false);
        normal.worker_numa_node = Some(1);
        let normal_result = evaluate_preflight(&report(), &normal);
        assert!(normal_result.can_run);
        assert!(!normal_result.certifiable);
        let mut certified = normal;
        certified.certification_mode = true;
        assert!(!evaluate_preflight(&report(), &certified).can_run);
    }

    #[test]
    fn missing_huge_pages_prevents_certification() {
        let mut environment = report();
        environment.huge_pages_free = Some(0);
        let result = evaluate_preflight(&environment, &request(true));
        assert!(!result.can_run);
        assert!(!result.certifiable);
    }

    #[test]
    fn duplicate_or_out_of_range_cpu_mapping_fails() {
        let mut requested = request(false);
        requested.worker_cpus = vec![2, 2, 99];
        assert!(!evaluate_preflight(&report(), &requested).can_run);
    }

    #[test]
    fn management_nic_is_rejected_when_explicitly_identified() {
        let mut request = request(false);
        request.management_pci_address = Some(request.pci_address.clone());
        let result = evaluate_preflight(&report(), &request);
        assert!(!result.can_run);
        assert_eq!(
            result
                .checks
                .iter()
                .find(|check| check.id == "MANAGEMENT_NIC_PROTECTION")
                .map(|check| check.severity),
            Some(PreflightSeverity::Fail)
        );
    }

    #[test]
    fn af_xdp_requires_queue_and_zero_copy_evidence_when_requested() {
        let mut environment = report();
        environment.nics[0].name = "eth0".to_owned();
        let request = AfXdpPreflightRequest {
            interface_name: "eth0".to_owned(),
            queue_id: 3,
            require_zero_copy: true,
        };
        let result = evaluate_af_xdp_preflight(&environment, &request);
        assert!(!result.can_run);
        assert!(!result.zero_copy_ready);
        assert!(result.checks.iter().any(|check| {
            check.id == "AF_XDP_ZERO_COPY" && check.severity == PreflightSeverity::Fail
        }));

        environment.af_xdp_zero_copy_capable = true;
        let result = evaluate_af_xdp_preflight(&environment, &request);
        assert!(result.can_run);
        assert!(result.zero_copy_ready);
    }

    #[test]
    fn af_xdp_compatibility_mode_warns_without_zero_copy() {
        let mut environment = report();
        environment.nics[0].name = "eth0".to_owned();
        let result = evaluate_af_xdp_preflight(
            &environment,
            &AfXdpPreflightRequest {
                interface_name: "eth0".to_owned(),
                queue_id: 0,
                require_zero_copy: false,
            },
        );
        assert!(result.can_run);
        assert!(result.checks.iter().any(|check| {
            check.id == "AF_XDP_ZERO_COPY" && check.severity == PreflightSeverity::Warn
        }));
    }
}
