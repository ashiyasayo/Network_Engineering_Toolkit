//! Bounded logical-CPU affinity boundary for data-plane workers.

#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#![cfg_attr(target_os = "linux", allow(unsafe_code))]

/// Linux `cpu_set_t` mask size supported by the raw syscall boundary.
pub const CPU_SET_BITS: u32 = 1024;
#[cfg(target_os = "linux")]
const MASK_BYTES: usize = (CPU_SET_BITS / 8) as usize;

/// CPU affinity validation or platform syscall failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AffinityError {
    /// No CPU was requested.
    Empty,
    /// CPU ID exceeds the bounded mask supported by this adapter.
    CpuOutOfRange(u32),
    /// Duplicate CPU IDs would make ownership ambiguous.
    DuplicateCpu(u32),
    /// Current platform has no implemented affinity adapter.
    UnsupportedPlatform,
    /// The platform rejected the affinity syscall.
    Syscall {
        /// Native errno returned by the operating system.
        errno: i32,
    },
}

impl std::fmt::Display for AffinityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("AFFINITY.EMPTY_CPU_SET"),
            Self::CpuOutOfRange(cpu) => write!(formatter, "AFFINITY.CPU_OUT_OF_RANGE: {cpu}"),
            Self::DuplicateCpu(cpu) => write!(formatter, "AFFINITY.DUPLICATE_CPU: {cpu}"),
            Self::UnsupportedPlatform => formatter.write_str("AFFINITY.UNSUPPORTED_PLATFORM"),
            Self::Syscall { errno } => write!(formatter, "AFFINITY.SYSCALL_FAILED: errno={errno}"),
        }
    }
}

impl std::error::Error for AffinityError {}

/// Validated, immutable CPU set used by one worker owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuSet {
    cpus: Vec<u32>,
}

impl CpuSet {
    /// Validate a CPU list without changing its ownership or ordering.
    ///
    /// # Errors
    ///
    /// Empty, duplicate, or out-of-range IDs are rejected.
    pub fn new(cpus: Vec<u32>) -> Result<Self, AffinityError> {
        if cpus.is_empty() {
            return Err(AffinityError::Empty);
        }
        let mut sorted = cpus.clone();
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            if pair[0] == pair[1] {
                return Err(AffinityError::DuplicateCpu(pair[0]));
            }
        }
        if let Some(cpu) = cpus.iter().copied().find(|cpu| *cpu >= CPU_SET_BITS) {
            return Err(AffinityError::CpuOutOfRange(cpu));
        }
        Ok(Self { cpus })
    }

    /// Construct a single-CPU ownership set.
    ///
    /// # Errors
    ///
    /// CPU ID outside the bounded mask is rejected.
    pub fn single(cpu: u32) -> Result<Self, AffinityError> {
        Self::new(vec![cpu])
    }

    /// CPU IDs in caller-provided order.
    #[must_use]
    pub fn cpus(&self) -> &[u32] {
        &self.cpus
    }
}

/// Pin the current OS thread to a validated logical CPU set.
///
/// This operation must be called from the worker thread itself; it does not
/// change the affinity of an executor's other threads.
///
/// # Errors
///
/// Invalid CPU sets, unsupported platforms, or a rejected OS syscall return an error.
pub fn pin_current_thread(cpu_set: &CpuSet) -> Result<(), AffinityError> {
    if cpu_set.cpus.is_empty() {
        return Err(AffinityError::Empty);
    }
    #[cfg(target_os = "linux")]
    {
        let mut mask = [0_u8; MASK_BYTES];
        for cpu in &cpu_set.cpus {
            let byte = (*cpu as usize) / 8;
            let bit = (*cpu as usize) % 8;
            mask[byte] |= 1_u8 << bit;
        }
        // SAFETY: pid 0 targets the calling thread; mask is a valid bounded cpu_set_t
        // representation for the Linux sched_setaffinity syscall.
        let result = unsafe { sched_setaffinity(0, mask.len(), mask.as_ptr().cast()) };
        if result != 0 {
            return Err(AffinityError::Syscall {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cpu_set;
        Err(AffinityError::UnsupportedPlatform)
    }
}

/// Whether this build has a native current-thread affinity adapter.
#[must_use]
pub const fn is_supported() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const std::ffi::c_void) -> i32;
}

#[cfg(test)]
mod tests {
    use super::{AffinityError, CPU_SET_BITS, CpuSet, is_supported};

    #[test]
    fn validates_bounded_unique_cpu_sets() {
        assert_eq!(CpuSet::new(Vec::new()), Err(AffinityError::Empty));
        assert_eq!(CpuSet::new(vec![2, 2]), Err(AffinityError::DuplicateCpu(2)));
        assert_eq!(
            CpuSet::new(vec![CPU_SET_BITS]),
            Err(AffinityError::CpuOutOfRange(CPU_SET_BITS))
        );
        assert_eq!(CpuSet::new(vec![3, 1]).expect("set").cpus(), &[3, 1]);
    }

    #[test]
    fn reports_platform_support_without_guessing() {
        assert_eq!(is_supported(), cfg!(target_os = "linux"));
    }
}
