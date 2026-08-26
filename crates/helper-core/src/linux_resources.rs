use nettool_error::{ErrorCode, NetToolError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const RESOURCE_STATE_VERSION: u32 = 1;
const DPDK_DRIVER: &str = "vfio-pci";

/// Kernel pseudo-filesystem access boundary。
pub trait KernelAccess {
    /// 讀取 symlink target。
    ///
    /// # Errors
    ///
    /// Kernel path 不存在或無法讀取時回傳 I/O error。
    fn read_link(&mut self, path: &Path) -> std::io::Result<PathBuf>;
    /// 讀取文字 pseudo-file。
    ///
    /// # Errors
    ///
    /// Kernel path 不存在或無法讀取時回傳 I/O error。
    fn read_to_string(&mut self, path: &Path) -> std::io::Result<String>;
    /// 寫入 pseudo-file。
    ///
    /// # Errors
    ///
    /// Kernel 拒絕寫入或 path 不存在時回傳 I/O error。
    fn write(&mut self, path: &Path, value: &[u8]) -> std::io::Result<()>;
}

/// Production kernel filesystem access。
#[derive(Default)]
pub struct SystemKernelAccess;

impl KernelAccess for SystemKernelAccess {
    fn read_link(&mut self, path: &Path) -> std::io::Result<PathBuf> {
        fs::read_link(path)
    }

    fn read_to_string(&mut self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }

    fn write(&mut self, path: &Path, value: &[u8]) -> std::io::Result<()> {
        fs::write(path, value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NicSnapshot {
    version: u32,
    operation_id: String,
    pci_address: String,
    original_driver: Option<String>,
    released: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct HugepageSnapshot {
    version: u32,
    operation_id: String,
    node: Option<u32>,
    page_size_kib: u64,
    previous_pages: u64,
    requested_pages: u64,
    released: bool,
}

/// Linux sysfs NIC/Huge Page privileged executor。
pub struct LinuxResourceExecutor<K> {
    kernel: K,
    sysfs_root: PathBuf,
    state_directory: PathBuf,
}

impl<K: KernelAccess> LinuxResourceExecutor<K> {
    /// 建立 executor；paths 必須 absolute。
    ///
    /// # Errors
    ///
    /// Path 非 absolute 或 state directory 無法建立時回傳錯誤。
    pub fn new(
        kernel: K,
        sysfs_root: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
    ) -> Result<Self, NetToolError> {
        let sysfs_root = sysfs_root.into();
        let state_directory = state_directory.into();
        if !sysfs_root.is_absolute() || !state_directory.is_absolute() {
            return Err(NetToolError::new(
                ErrorCode::InvalidArgument,
                "resource executor paths must be absolute",
                false,
            ));
        }
        fs::create_dir_all(&state_directory).map_err(persistence_error)?;
        Ok(Self {
            kernel,
            sysfs_root,
            state_directory,
        })
    }

    /// Snapshot 原 driver 後將 NIC 綁定至固定的 `vfio-pci` driver。
    ///
    /// # Errors
    ///
    /// Snapshot、sysfs write 或 read-back verification 失敗時回傳錯誤。
    pub fn prepare_dpdk(
        &mut self,
        operation_id: &str,
        pci_address: &str,
    ) -> Result<ValueResult, NetToolError> {
        validate_pci_address(pci_address)?;
        let path = self.state_path("nic", operation_id);
        let mut snapshot = if path.exists() {
            let existing: NicSnapshot = read_state(&path)?;
            if existing.operation_id != operation_id || existing.pci_address != pci_address {
                return Err(operation_conflict());
            }
            existing
        } else {
            let snapshot = NicSnapshot {
                version: RESOURCE_STATE_VERSION,
                operation_id: operation_id.to_owned(),
                pci_address: pci_address.to_owned(),
                original_driver: self.current_driver(pci_address)?,
                released: false,
            };
            write_state(&path, &snapshot)?;
            snapshot
        };
        if snapshot.released {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                "NIC prepare operation was already released",
                false,
            ));
        }
        self.bind_driver(pci_address, Some(DPDK_DRIVER))?;
        snapshot.released = false;
        write_state(&path, &snapshot)?;
        Ok(ValueResult {
            original_driver: snapshot.original_driver,
            active_driver: Some(DPDK_DRIVER.to_owned()),
            previous_pages: None,
            active_pages: None,
        })
    }

    /// 只依 helper-owned prepare snapshot 恢復 NIC driver。
    ///
    /// # Errors
    ///
    /// Snapshot 不符、sysfs write 或 verification 失敗時回傳錯誤。
    pub fn restore_driver(
        &mut self,
        prepare_operation_id: &str,
        pci_address: &str,
    ) -> Result<ValueResult, NetToolError> {
        validate_pci_address(pci_address)?;
        let path = self.state_path("nic", prepare_operation_id);
        let mut snapshot: NicSnapshot = read_state(&path)?;
        if snapshot.version != RESOURCE_STATE_VERSION
            || snapshot.operation_id != prepare_operation_id
            || snapshot.pci_address != pci_address
        {
            return Err(operation_conflict());
        }
        if !snapshot.released {
            self.bind_driver(pci_address, snapshot.original_driver.as_deref())?;
            self.kernel
                .write(
                    &self
                        .sysfs_root
                        .join("bus/pci/devices")
                        .join(pci_address)
                        .join("driver_override"),
                    b"\n",
                )
                .map_err(|error| kernel_error("clear PCI driver override", error))?;
            snapshot.released = true;
            write_state(&path, &snapshot)?;
        }
        Ok(ValueResult {
            original_driver: snapshot.original_driver.clone(),
            active_driver: snapshot.original_driver,
            previous_pages: None,
            active_pages: None,
        })
    }

    /// Snapshot 原 Huge Page count 後寫入並讀回驗證。
    ///
    /// # Errors
    ///
    /// Operation 衝突、sysfs path 不存在、write 或 verification 失敗時回傳錯誤。
    pub fn prepare_hugepages(
        &mut self,
        operation_id: &str,
        node: Option<u32>,
        pages: u64,
        page_size_kib: u64,
    ) -> Result<ValueResult, NetToolError> {
        validate_hugepages(pages, page_size_kib)?;
        let state_path = self.state_path("hugepage", operation_id);
        let sysfs_path = self.hugepage_path(node, page_size_kib);
        let mut snapshot = if state_path.exists() {
            let existing: HugepageSnapshot = read_state(&state_path)?;
            if existing.operation_id != operation_id
                || existing.node != node
                || existing.page_size_kib != page_size_kib
                || existing.requested_pages != pages
            {
                return Err(operation_conflict());
            }
            existing
        } else {
            let previous_pages = self.read_count(&sysfs_path)?;
            let snapshot = HugepageSnapshot {
                version: RESOURCE_STATE_VERSION,
                operation_id: operation_id.to_owned(),
                node,
                page_size_kib,
                previous_pages,
                requested_pages: pages,
                released: false,
            };
            write_state(&state_path, &snapshot)?;
            snapshot
        };
        if snapshot.released {
            return Err(NetToolError::new(
                ErrorCode::InvalidState,
                "Huge Page prepare operation was already released",
                false,
            ));
        }
        self.write_count(&sysfs_path, pages)?;
        snapshot.released = false;
        write_state(&state_path, &snapshot)?;
        Ok(ValueResult {
            original_driver: None,
            active_driver: None,
            previous_pages: Some(snapshot.previous_pages),
            active_pages: Some(pages),
        })
    }

    /// 依 prepare operation snapshot 恢復 Huge Page count；重送為冪等操作。
    ///
    /// # Errors
    ///
    /// Snapshot 不存在、write 或 verification 失敗時回傳錯誤。
    pub fn release_hugepages(
        &mut self,
        prepare_operation_id: &str,
    ) -> Result<ValueResult, NetToolError> {
        let state_path = self.state_path("hugepage", prepare_operation_id);
        let mut snapshot: HugepageSnapshot = read_state(&state_path)?;
        if snapshot.version != RESOURCE_STATE_VERSION
            || snapshot.operation_id != prepare_operation_id
        {
            return Err(operation_conflict());
        }
        let sysfs_path = self.hugepage_path(snapshot.node, snapshot.page_size_kib);
        if !snapshot.released {
            self.write_count(&sysfs_path, snapshot.previous_pages)?;
            snapshot.released = true;
            write_state(&state_path, &snapshot)?;
        }
        Ok(ValueResult {
            original_driver: None,
            active_driver: None,
            previous_pages: Some(snapshot.previous_pages),
            active_pages: Some(snapshot.previous_pages),
        })
    }

    fn current_driver(&mut self, pci_address: &str) -> Result<Option<String>, NetToolError> {
        let path = self
            .sysfs_root
            .join("bus/pci/devices")
            .join(pci_address)
            .join("driver");
        match self.kernel.read_link(&path) {
            Ok(target) => target
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| Some(name.to_owned()))
                .ok_or_else(|| execution_error("PCI driver symlink is invalid")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(kernel_error("read PCI driver", error)),
        }
    }

    fn bind_driver(
        &mut self,
        pci_address: &str,
        target_driver: Option<&str>,
    ) -> Result<(), NetToolError> {
        let device = self.sysfs_root.join("bus/pci/devices").join(pci_address);
        let current = self.current_driver(pci_address)?;
        if current.as_deref() == target_driver {
            return Ok(());
        }
        let override_value = target_driver.unwrap_or("");
        self.kernel
            .write(&device.join("driver_override"), override_value.as_bytes())
            .map_err(|error| kernel_error("write PCI driver override", error))?;
        if let Some(driver) = current {
            self.kernel
                .write(
                    &self
                        .sysfs_root
                        .join("bus/pci/drivers")
                        .join(driver)
                        .join("unbind"),
                    pci_address.as_bytes(),
                )
                .map_err(|error| kernel_error("unbind PCI driver", error))?;
        }
        if target_driver.is_some() {
            self.kernel
                .write(
                    &self.sysfs_root.join("bus/pci/drivers_probe"),
                    pci_address.as_bytes(),
                )
                .map_err(|error| kernel_error("probe PCI driver", error))?;
        }
        if self.current_driver(pci_address)?.as_deref() != target_driver {
            return Err(execution_error("PCI driver read-back verification failed"));
        }
        Ok(())
    }

    fn hugepage_path(&self, node: Option<u32>, page_size_kib: u64) -> PathBuf {
        let suffix = format!("hugepages/hugepages-{page_size_kib}kB/nr_hugepages");
        node.map_or_else(
            || self.sysfs_root.join("kernel/mm").join(&suffix),
            |node| {
                self.sysfs_root
                    .join("devices/system/node")
                    .join(format!("node{node}"))
                    .join(&suffix)
            },
        )
    }

    fn read_count(&mut self, path: &Path) -> Result<u64, NetToolError> {
        self.kernel
            .read_to_string(path)
            .map_err(|error| kernel_error("read Huge Page count", error))?
            .trim()
            .parse()
            .map_err(|_| execution_error("Huge Page count is invalid"))
    }

    fn write_count(&mut self, path: &Path, pages: u64) -> Result<(), NetToolError> {
        self.kernel
            .write(path, pages.to_string().as_bytes())
            .map_err(|error| kernel_error("write Huge Page count", error))?;
        if self.read_count(path)? != pages {
            return Err(execution_error("Huge Page read-back verification failed"));
        }
        Ok(())
    }

    fn state_path(&self, kind: &str, operation_id: &str) -> PathBuf {
        let digest = Sha256::digest(operation_id.as_bytes());
        self.state_directory.join(format!("{kind}-{digest:x}.json"))
    }
}

/// Resource operation 的 structured result。
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValueResult {
    /// Prepare 前 driver。
    pub original_driver: Option<String>,
    /// Operation 後 driver。
    pub active_driver: Option<String>,
    /// Prepare 前 Huge Page count。
    pub previous_pages: Option<u64>,
    /// Operation 後 Huge Page count。
    pub active_pages: Option<u64>,
}

fn validate_pci_address(value: &str) -> Result<(), NetToolError> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10) || byte.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "PCI address must use dddd:bb:ss.f format",
            false,
        ))
    }
}

fn validate_hugepages(pages: u64, page_size_kib: u64) -> Result<(), NetToolError> {
    if pages == 0
        || page_size_kib == 0
        || pages
            .checked_mul(page_size_kib)
            .is_none_or(|total| total > 1_073_741_824)
    {
        Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "Huge Page request is outside the safety limit",
            false,
        ))
    } else {
        Ok(())
    }
}

fn write_state(path: &Path, state: &impl Serialize) -> Result<(), NetToolError> {
    let temporary = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(state).map_err(state_error)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(persistence_error)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(persistence_error)?;
    fs::rename(temporary, path).map_err(persistence_error)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(persistence_error)?;
    }
    Ok(())
}

fn read_state<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, NetToolError> {
    let bytes = fs::read(path).map_err(persistence_error)?;
    serde_json::from_slice(&bytes).map_err(state_error)
}

fn operation_conflict() -> NetToolError {
    NetToolError::new(
        ErrorCode::OperationConflict,
        "resource operation ID was reused with different arguments",
        false,
    )
}

fn execution_error(message: &str) -> NetToolError {
    NetToolError::new(ErrorCode::HelperExecutionFailed, message, false)
}

#[allow(clippy::needless_pass_by_value)]
fn kernel_error(context: &str, error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::HelperExecutionFailed,
        format!("{context}: {error}"),
        error.kind() == std::io::ErrorKind::Interrupted,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn persistence_error(error: std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("resource snapshot persistence failed: {error}"),
        true,
    )
}

#[allow(clippy::needless_pass_by_value)]
fn state_error(error: serde_json::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PersistenceFailed,
        format!("resource snapshot is invalid: {error}"),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{KernelAccess, LinuxResourceExecutor};
    use std::collections::BTreeMap;
    use std::io::{Error, ErrorKind};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct FakeKernel {
        files: BTreeMap<PathBuf, Vec<u8>>,
        driver: Option<String>,
    }

    impl KernelAccess for FakeKernel {
        fn read_link(&mut self, path: &Path) -> std::io::Result<PathBuf> {
            if path.ends_with("driver") {
                self.driver
                    .as_ref()
                    .map(|driver| PathBuf::from("/sys/bus/pci/drivers").join(driver))
                    .ok_or_else(|| Error::from(ErrorKind::NotFound))
            } else {
                Err(Error::from(ErrorKind::NotFound))
            }
        }

        fn read_to_string(&mut self, path: &Path) -> std::io::Result<String> {
            self.files
                .get(path)
                .map(|value| String::from_utf8_lossy(value).into_owned())
                .ok_or_else(|| Error::from(ErrorKind::NotFound))
        }

        fn write(&mut self, path: &Path, value: &[u8]) -> std::io::Result<()> {
            if path.ends_with("driver_override") {
                let driver = String::from_utf8_lossy(value).into_owned();
                self.files.insert(path.to_path_buf(), value.to_vec());
                if driver.is_empty() {
                    self.driver = None;
                }
            } else if path.ends_with("drivers_probe") {
                let device = path
                    .parent()
                    .ok_or_else(|| Error::from(ErrorKind::InvalidInput))?
                    .join("devices")
                    .join(String::from_utf8_lossy(value).as_ref())
                    .join("driver_override");
                self.driver = self
                    .files
                    .get(&device)
                    .map(|driver| String::from_utf8_lossy(driver).into_owned());
            } else if path.ends_with("unbind") {
                self.driver = None;
            } else {
                self.files.insert(path.to_path_buf(), value.to_vec());
            }
            Ok(())
        }
    }

    fn state_directory() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("nettool-resource-test-{}-{id}", std::process::id()))
    }

    fn sysfs_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "nettool-resource-sysfs-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn hugepage_prepare_and_release_restore_original_count() {
        let state = state_directory();
        let sysfs = sysfs_root();
        let path = sysfs.join("kernel/mm/hugepages/hugepages-2048kB/nr_hugepages");
        let mut kernel = FakeKernel::default();
        kernel.files.insert(path, b"8".to_vec());
        let mut executor = LinuxResourceExecutor::new(kernel, &sysfs, &state).expect("executor");
        let prepared = executor
            .prepare_hugepages("op-1", None, 16, 2048)
            .expect("prepare");
        assert_eq!(prepared.previous_pages, Some(8));
        assert_eq!(prepared.active_pages, Some(16));
        let released = executor.release_hugepages("op-1").expect("release");
        assert_eq!(released.active_pages, Some(8));
        let _ = std::fs::remove_dir_all(state);
    }

    #[test]
    fn nic_restore_uses_helper_snapshot_not_caller_driver() {
        let state = state_directory();
        let kernel = FakeKernel {
            driver: Some("ixgbe".into()),
            ..FakeKernel::default()
        };
        let sysfs = sysfs_root();
        let mut executor = LinuxResourceExecutor::new(kernel, &sysfs, &state).expect("executor");
        let prepared = executor
            .prepare_dpdk("op-nic", "0000:01:00.0")
            .expect("prepare");
        assert_eq!(prepared.active_driver.as_deref(), Some("vfio-pci"));
        let restored = executor
            .restore_driver("op-nic", "0000:01:00.0")
            .expect("restore");
        assert_eq!(restored.active_driver.as_deref(), Some("ixgbe"));
        let _ = std::fs::remove_dir_all(state);
    }
}
