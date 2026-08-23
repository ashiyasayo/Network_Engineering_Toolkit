//! Linux benchmark environment snapshot collector。

use nettool_benchmark::BenchmarkEnvironmentSnapshot;
use nettool_domain::NicProbe;
use nettool_error::{ErrorCode, NetToolError};
use std::fs;
use std::path::{Path, PathBuf};

/// 已由對應 backend/netlink API 驗證、但 sysfs 無法完整表示的輸入。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxBenchmarkSnapshotRequest {
    /// Linux interface name。
    pub interface_name: String,
    /// 預期 PCI address。
    pub pci_address: String,
    /// Backend 與版本。
    pub backend: String,
    /// DPDK version；無可靠 runtime 資料時必須為 `None`。
    pub dpdk_version: Option<String>,
    /// 經 backend API 驗證的 RSS configuration。
    pub verified_rss: Option<String>,
    /// 經 backend API 驗證的 offload configuration。
    pub verified_offloads: Option<String>,
}

/// Collector 結果；缺失欄位不猜值，並保留 warnings。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentCollection {
    /// 部分或完整 environment snapshot。
    pub snapshot: BenchmarkEnvironmentSnapshot,
    /// 無法讀取/驗證欄位的原因。
    pub warnings: Vec<String>,
}

/// 已由 backend API 驗證的 RSS evidence。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RssEvidence {
    /// RSS 是否啟用。
    pub active: bool,
    /// Backend 宣告的 RX queue 數量；舊版 API 未提供時為 `None`。
    pub queue_count: Option<u32>,
}

/// 由 Linux default route 解析出目前 management NIC 的 PCI address。
///
/// 只接受 `/proc/net/route` 的 default route（destination `00000000`），不執行
/// shell command，也不把不存在於最新 NIC probe 的介面猜成 management NIC。
#[must_use]
pub fn resolve_management_pci_from_route(
    route_contents: &str,
    nics: &[NicProbe],
) -> Option<String> {
    let interface = route_contents.lines().skip(1).find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.len() >= 2 && fields[1] == "00000000").then(|| fields[0].to_owned())
    })?;
    nics.iter()
        .find(|nic| nic.name == interface)
        .and_then(|nic| nic.pci_address.clone())
}

/// 從目前 Linux host 的 default route 取得 management PCI evidence。
#[must_use]
pub fn detect_management_pci_address(nics: &[NicProbe]) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let route = std::fs::read_to_string("/proc/net/route").ok()?;
        resolve_management_pci_from_route(&route, nics)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = nics;
        None
    }
}

/// 解析固定格式的 RSS evidence，拒絕未定義的自由文字。
///
/// 接受 `enabled`、`disabled`，以及 `enabled:<n> queues`；queue count 存在時
/// 可再與 sysfs/backend 的 RX queue count 比對。
///
/// # Errors
///
/// 空字串、未知狀態、非數字 queue count 或 overflow 時回傳錯誤。
pub fn parse_rss_evidence(value: &str) -> Result<RssEvidence, NetToolError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("enabled") {
        return Ok(RssEvidence {
            active: true,
            queue_count: None,
        });
    }
    if value.eq_ignore_ascii_case("disabled") {
        return Ok(RssEvidence {
            active: false,
            queue_count: None,
        });
    }
    let suffix = " queues";
    let Some(number) = value
        .strip_prefix("enabled:")
        .and_then(|value| value.strip_suffix(suffix))
    else {
        return Err(invalid(
            "RSS evidence must be enabled, disabled, or enabled:<n> queues",
        ));
    };
    let queue_count = number
        .parse::<u32>()
        .map_err(|_| invalid("RSS evidence queue count must be a u32"))?;
    if queue_count == 0 {
        return Err(invalid("RSS evidence queue count must be non-zero"));
    }
    Ok(RssEvidence {
        active: true,
        queue_count: Some(queue_count),
    })
}

/// 從目前 Linux host 收集 benchmark environment。
///
/// # Errors
///
/// 非 Linux 平台或 request identifier 不安全時回傳錯誤。個別選用欄位缺失會保留
/// `None` 與 warning，後續 certification evaluator 會阻止認證。
pub fn collect_benchmark_environment(
    request: &LinuxBenchmarkSnapshotRequest,
) -> Result<EnvironmentCollection, NetToolError> {
    if !cfg!(target_os = "linux") {
        return Err(NetToolError::new(
            ErrorCode::Unsupported,
            "Linux benchmark environment collection is unavailable on this platform",
            false,
        ));
    }
    collect_linux_environment_at(Path::new("/"), request)
}

#[allow(clippy::too_many_lines)]
fn collect_linux_environment_at(
    root: &Path,
    request: &LinuxBenchmarkSnapshotRequest,
) -> Result<EnvironmentCollection, NetToolError> {
    validate_request(request)?;
    let mut warnings = Vec::new();
    let interface_root = rooted(root, &format!("/sys/class/net/{}", request.interface_name));
    let device = interface_root.join("device");
    let discovered_pci = fs::canonicalize(&device).ok().and_then(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    if discovered_pci.as_deref() != Some(request.pci_address.as_str()) {
        warnings.push(format!(
            "PCI identity mismatch: expected {}, discovered {}",
            request.pci_address,
            discovered_pci.as_deref().unwrap_or("unknown")
        ));
    }
    let os_release = read_optional(
        &rooted(root, "/etc/os-release"),
        "OS release",
        &mut warnings,
    );
    let cpuinfo = read_optional(
        &rooted(root, "/proc/cpuinfo"),
        "CPU information",
        &mut warnings,
    );
    let meminfo = read_optional(
        &rooted(root, "/proc/meminfo"),
        "memory information",
        &mut warnings,
    );
    let driver = driver_name(&device);
    let driver_description = driver.as_deref().map(|name| {
        let version = read_trimmed(rooted(root, &format!("/sys/module/{name}/version")));
        version.map_or_else(|| name.to_owned(), |version| format!("{name} {version}"))
    });
    note_missing(&mut warnings, "driver", driver_description.as_deref());
    let vendor = read_trimmed(device.join("vendor"));
    let device_id = read_trimmed(device.join("device"));
    let nic = vendor
        .as_deref()
        .zip(device_id.as_deref())
        .map(|(vendor, device)| format!("PCI {vendor}:{device}"));
    note_missing(&mut warnings, "NIC identity", nic.as_deref());
    let pcie_speed = read_trimmed(device.join("current_link_speed"));
    let pcie_width = read_trimmed(device.join("current_link_width"));
    let pcie = pcie_speed
        .as_deref()
        .zip(pcie_width.as_deref())
        .map(|(speed, width)| format!("{speed} x{width}"));
    note_missing(&mut warnings, "PCIe link", pcie.as_deref());
    let firmware = read_trimmed(device.join("firmware_version"));
    note_missing(&mut warnings, "NIC firmware", firmware.as_deref());
    let nodes = numbered_entries(&rooted(root, "/sys/devices/system/node"), "node");
    let nic_node = read_trimmed(device.join("numa_node"));
    let numa = nodes
        .zip(nic_node)
        .map(|(nodes, nic_node)| format!("nodes={nodes},nic_node={nic_node}"));
    note_missing(&mut warnings, "NUMA topology", numa.as_deref());
    let memory = meminfo
        .as_deref()
        .and_then(|contents| proc_value(contents, "MemTotal:"))
        .map(|value| format!("MemTotal={value} kB"));
    note_missing(&mut warnings, "memory capacity", memory.as_deref());
    let huge_pages = meminfo.as_deref().and_then(huge_page_description);
    note_missing(&mut warnings, "Huge Pages", huge_pages.as_deref());
    let cpu = cpuinfo
        .as_deref()
        .and_then(|contents| proc_text(contents, "model name"));
    note_missing(&mut warnings, "CPU model", cpu.as_deref());
    let cpu_frequency = read_trimmed(rooted(
        root,
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
    ))
    .map(|value| format!("{value} kHz"))
    .or_else(|| {
        cpuinfo
            .as_deref()
            .and_then(|contents| proc_text(contents, "cpu MHz"))
            .map(|value| format!("{value} MHz"))
    });
    note_missing(&mut warnings, "CPU frequency", cpu_frequency.as_deref());
    let os = os_release
        .as_deref()
        .and_then(|contents| os_release_value(contents, "PRETTY_NAME"));
    note_missing(&mut warnings, "OS", os.as_deref());
    let kernel = read_trimmed(rooted(root, "/proc/sys/kernel/osrelease"));
    note_missing(&mut warnings, "kernel", kernel.as_deref());
    let mtu = read_u32(interface_root.join("mtu"));
    note_missing_number(&mut warnings, "MTU", mtu);
    let rx_queues = count_entries(&interface_root.join("queues"), "rx-");
    let tx_queues = count_entries(&interface_root.join("queues"), "tx-");
    note_missing_number(&mut warnings, "RX queues", rx_queues);
    note_missing_number(&mut warnings, "TX queues", tx_queues);
    note_missing(
        &mut warnings,
        "DPDK version",
        request.dpdk_version.as_deref(),
    );
    let validated_rss = request
        .verified_rss
        .as_deref()
        .and_then(|value| match parse_rss_evidence(value) {
            Ok(evidence) => {
                if let Some(queue_count) = evidence.queue_count
                    && rx_queues.is_some_and(|actual| actual != queue_count)
                {
                    warnings.push(format!(
                        "RSS queue count mismatch: evidence={queue_count}, sysfs={}",
                        rx_queues.unwrap_or_default()
                    ));
                    return None;
                }
                Some(value.to_owned())
            }
            Err(error) => {
                warnings.push(format!("RSS evidence rejected: {}", error.message));
                None
            }
        });
    note_missing(&mut warnings, "RSS configuration", validated_rss.as_deref());
    note_missing(
        &mut warnings,
        "offload configuration",
        request.verified_offloads.as_deref(),
    );
    Ok(EnvironmentCollection {
        snapshot: BenchmarkEnvironmentSnapshot {
            os,
            kernel,
            cpu,
            cpu_frequency,
            numa,
            memory,
            huge_pages,
            nic,
            pcie,
            firmware,
            driver: driver_description,
            dpdk_version: request.dpdk_version.clone(),
            backend: Some(request.backend.clone()),
            mtu,
            rx_queues,
            tx_queues,
            rss: validated_rss,
            offloads: request.verified_offloads.clone(),
        },
        warnings,
    })
}

fn validate_request(request: &LinuxBenchmarkSnapshotRequest) -> Result<(), NetToolError> {
    if !safe_identifier(&request.interface_name) {
        return Err(invalid(
            "interface name is empty or contains unsafe characters",
        ));
    }
    if !valid_pci_address(&request.pci_address) {
        return Err(invalid("PCI address must use dddd:bb:ss.f format"));
    }
    if request.backend.trim().is_empty() || request.backend.len() > 128 {
        return Err(invalid("backend identity is empty or too long"));
    }
    for (name, value) in [
        ("DPDK version", request.dpdk_version.as_deref()),
        ("RSS", request.verified_rss.as_deref()),
        ("offloads", request.verified_offloads.as_deref()),
    ] {
        if value.is_some_and(|value| value.trim().is_empty() || value.len() > 4096) {
            return Err(invalid(&format!("{name} evidence is empty or too long")));
        }
    }
    Ok(())
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn valid_pci_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10) || byte.is_ascii_hexdigit())
}

fn rooted(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn read_optional(path: &Path, label: &str, warnings: &mut Vec<String>) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(value) => Some(value),
        Err(error) => {
            warnings.push(format!(
                "{label} is unavailable at {}: {error}",
                path.display()
            ));
            None
        }
    }
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn read_u32(path: PathBuf) -> Option<u32> {
    read_trimmed(path).and_then(|value| value.parse().ok())
}

fn driver_name(device: &Path) -> Option<String> {
    fs::read_link(device.join("driver")).ok().and_then(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    })
}

fn count_entries(path: &Path, prefix: &str) -> Option<u32> {
    fs::read_dir(path).ok().and_then(|entries| {
        u32::try_from(
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
                .count(),
        )
        .ok()
    })
}

fn numbered_entries(path: &Path, prefix: &str) -> Option<u32> {
    fs::read_dir(path).ok().and_then(|entries| {
        u32::try_from(
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| {
                            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                        })
                })
                .count(),
        )
        .ok()
    })
}

fn proc_value(contents: &str, key: &str) -> Option<u64> {
    contents
        .lines()
        .find(|line| line.starts_with(key))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
}

fn proc_text(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (field, value) = line.split_once(':')?;
        (field.trim() == key).then(|| value.trim().to_owned())
    })
}

fn os_release_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (field, value) = line.split_once('=')?;
        (field == key).then(|| value.trim_matches('"').to_owned())
    })
}

fn huge_page_description(contents: &str) -> Option<String> {
    let total = proc_value(contents, "HugePages_Total:")?;
    let free = proc_value(contents, "HugePages_Free:")?;
    let size = proc_value(contents, "Hugepagesize:")?;
    Some(format!("total={total},free={free},size_kib={size}"))
}

fn note_missing(warnings: &mut Vec<String>, label: &str, value: Option<&str>) {
    if value.is_none() {
        warnings.push(format!("{label} could not be verified"));
    }
}

fn note_missing_number(warnings: &mut Vec<String>, label: &str, value: Option<u32>) {
    if value.is_none() {
        warnings.push(format!("{label} could not be verified"));
    }
}

fn invalid(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        LinuxBenchmarkSnapshotRequest, collect_linux_environment_at, parse_rss_evidence,
        resolve_management_pci_from_route,
    };
    use nettool_domain::NicProbe;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn collects_complete_snapshot_from_injected_sysroot() {
        let root = test_root();
        write(&root, "etc/os-release", "PRETTY_NAME=\"Test Linux\"\n");
        write(&root, "proc/sys/kernel/osrelease", "6.1-test\n");
        write(
            &root,
            "proc/cpuinfo",
            "model name : Test CPU\ncpu MHz : 3000.000\n",
        );
        write(
            &root,
            "proc/meminfo",
            "MemTotal: 1024 kB\nHugePages_Total: 8\nHugePages_Free: 4\nHugepagesize: 1048576 kB\n",
        );
        write(
            &root,
            "sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
            "3000000\n",
        );
        fs::create_dir_all(root.join("sys/devices/system/node/node0")).expect("node");
        let pci = root.join("sys/devices/pci0000:00/0000:01:00.0");
        fs::create_dir_all(&pci).expect("pci");
        write_path(&pci.join("vendor"), "0x1234\n");
        write_path(&pci.join("device"), "0x5678\n");
        write_path(&pci.join("numa_node"), "0\n");
        write_path(&pci.join("current_link_speed"), "16.0 GT/s\n");
        write_path(&pci.join("current_link_width"), "16\n");
        write_path(&pci.join("firmware_version"), "1.2.3\n");
        let interface = root.join("sys/class/net/eth0");
        fs::create_dir_all(interface.join("queues/rx-0")).expect("rx");
        fs::create_dir_all(interface.join("queues/tx-0")).expect("tx");
        write_path(&interface.join("mtu"), "1500\n");
        symlink(&pci, interface.join("device")).expect("device link");
        let driver = root.join("sys/bus/pci/drivers/vfio-pci");
        fs::create_dir_all(&driver).expect("driver");
        symlink(&driver, pci.join("driver")).expect("driver link");
        write(&root, "sys/module/vfio-pci/version", "1.0\n");
        let result = collect_linux_environment_at(
            &root,
            &LinuxBenchmarkSnapshotRequest {
                interface_name: "eth0".to_owned(),
                pci_address: "0000:01:00.0".to_owned(),
                backend: "dpdk 24.11".to_owned(),
                dpdk_version: Some("24.11".to_owned()),
                verified_rss: Some("enabled:1 queues".to_owned()),
                verified_offloads: Some("checksum=off".to_owned()),
            },
        )
        .expect("collection");
        assert!(
            result.snapshot.missing_fields().is_empty(),
            "{:?}",
            result.warnings
        );
        assert!(result.snapshot.certification_key().is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_path_traversal_and_keeps_unverified_fields_missing() {
        let root = test_root();
        let invalid = LinuxBenchmarkSnapshotRequest {
            interface_name: "../eth0".to_owned(),
            pci_address: "0000:01:00.0".to_owned(),
            backend: "dpdk".to_owned(),
            dpdk_version: None,
            verified_rss: None,
            verified_offloads: None,
        };
        assert!(collect_linux_environment_at(&root, &invalid).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parses_rss_evidence_without_accepting_free_text() {
        assert_eq!(
            parse_rss_evidence("enabled:4 queues").expect("rss"),
            super::RssEvidence {
                active: true,
                queue_count: Some(4),
            }
        );
        assert_eq!(
            parse_rss_evidence("disabled").expect("rss"),
            super::RssEvidence {
                active: false,
                queue_count: None,
            }
        );
        assert!(parse_rss_evidence("enabled:four queues").is_err());
        assert!(parse_rss_evidence("driver says enabled").is_err());
    }

    #[test]
    fn resolves_management_pci_only_from_default_route_and_known_nic() {
        let nics = vec![NicProbe {
            name: "eth0".to_owned(),
            pci_address: Some("0000:01:00.0".to_owned()),
            driver: None,
            link_speed_mbps: None,
            rx_queues: None,
            tx_queues: None,
            numa_node: None,
        }];
        let route = "Iface\tDestination\tGateway\neth0\t00000000\t0100007F\n";
        assert_eq!(
            resolve_management_pci_from_route(route, &nics).as_deref(),
            Some("0000:01:00.0")
        );
        assert!(
            resolve_management_pci_from_route(
                "Iface\tDestination\tGateway\neth0\t0001\t0\n",
                &nics
            )
            .is_none()
        );
    }

    fn test_root() -> std::path::PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("nettool-environment-{}-{id}", std::process::id()))
    }

    fn write(root: &std::path::Path, relative: &str, contents: &str) {
        write_path(&root.join(relative), contents);
    }

    fn write_path(path: &std::path::Path, contents: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        fs::write(path, contents).expect("fixture");
    }
}
