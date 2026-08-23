use nettool_error::{ErrorCode, NetToolError};

/// DPDK worker 可使用的 logical CPU；呼叫端必須先排除系統與控制面保留核心。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPlaneCpu {
    /// OS logical CPU ID。
    pub logical_id: u32,
    /// CPU 所屬 NUMA node。
    pub numa_node: i32,
}

/// Queue 數量選擇策略。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueSelection {
    /// 依 NIC、同 NUMA 可用核心與設定上限取最小值。
    Auto,
    /// 使用者明確指定 queue 數量。
    Explicit(u16),
}

/// NIC 可配置的硬體 queue 上限。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NicQueueCapacity {
    /// RX queue 上限。
    pub receive: u16,
    /// TX queue 上限。
    pub transmit: u16,
}

/// 單一 RX queue 與其唯一 worker core 的 ownership。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxQueueAssignment {
    /// DPDK RX queue ID。
    pub queue_id: u16,
    /// 唯一 polling 此 queue 的 logical CPU。
    pub logical_cpu: u32,
}

/// 啟動 DPDK port 前完成的 queue/core 規劃。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuePlan {
    /// NIC NUMA node。
    pub numa_node: i32,
    /// 實際 RX queue 數量。
    pub rx_queues: u16,
    /// 實際 TX queue 數量。
    pub tx_queues: u16,
    /// 每個 RX queue 的唯一 worker owner。
    pub rx_assignments: Vec<RxQueueAssignment>,
}

impl QueuePlan {
    /// 驗證 queue plan 可安全交給 native worker orchestration。
    ///
    /// # Errors
    ///
    /// RX/TX queue 為零、assignment 數量不符、queue ID 不連續或 CPU owner 重複時回傳錯誤。
    pub fn validate(&self) -> Result<(), NetToolError> {
        if self.rx_queues == 0 || self.tx_queues == 0 {
            return Err(invalid("queue plan RX/TX queues must be non-zero"));
        }
        if self.rx_assignments.len() != usize::from(self.rx_queues) {
            return Err(invalid(
                "queue plan assignment count does not match RX queues",
            ));
        }
        let mut cpus = self
            .rx_assignments
            .iter()
            .map(|assignment| assignment.logical_cpu)
            .collect::<Vec<_>>();
        cpus.sort_unstable();
        if cpus.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("queue plan CPU owners must be unique"));
        }
        if self
            .rx_assignments
            .iter()
            .enumerate()
            .any(|(index, assignment)| {
                assignment.queue_id != u16::try_from(index).unwrap_or(u16::MAX)
            })
        {
            return Err(invalid("queue plan queue IDs must be contiguous"));
        }
        Ok(())
    }
}

/// 建立符合 one-queue/one-worker 與 NUMA locality 的 queue plan。
///
/// `available_cpus` 必須是 resource manager 已排除 OS、control、GUI、storage 與其他
/// session 後的結果，避免此層從 CPU thread count 猜測可用資源。
///
/// # Errors
///
/// Queue capacity、設定上限、同 NUMA CPU 數量不足或 CPU ID 重複時回傳錯誤。
pub fn plan_queues(
    nic_numa_node: i32,
    nic_capacity: NicQueueCapacity,
    available_cpus: &[DataPlaneCpu],
    configured_maximum: u16,
    selection: QueueSelection,
) -> Result<QueuePlan, NetToolError> {
    if nic_capacity.receive == 0 || nic_capacity.transmit == 0 || configured_maximum == 0 {
        return Err(invalid(
            "NIC queue capacity and configured maximum must be non-zero",
        ));
    }

    let mut local_cpus = available_cpus
        .iter()
        .filter(|cpu| cpu.numa_node == nic_numa_node)
        .map(|cpu| cpu.logical_id)
        .collect::<Vec<_>>();
    local_cpus.sort_unstable();
    if local_cpus.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("available data-plane CPU IDs must be unique"));
    }

    let automatic = usize::from(nic_capacity.receive)
        .min(local_cpus.len())
        .min(usize::from(configured_maximum));
    let requested = match selection {
        QueueSelection::Auto => automatic,
        QueueSelection::Explicit(value) => usize::from(value),
    };
    if requested == 0 {
        return Err(invalid("no same-NUMA data-plane CPU is available"));
    }
    if requested > usize::from(nic_capacity.receive)
        || requested > usize::from(configured_maximum)
        || requested > local_cpus.len()
    {
        return Err(invalid(
            "requested RX queues exceed NIC, configured, or same-NUMA CPU capacity",
        ));
    }
    let tx_queues = requested.min(usize::from(nic_capacity.transmit));
    if tx_queues == 0 {
        return Err(invalid("no TX queue is available"));
    }
    let rx_queues = u16::try_from(requested).map_err(|_| invalid("RX queue count overflow"))?;
    let tx_queues = u16::try_from(tx_queues).map_err(|_| invalid("TX queue count overflow"))?;
    let rx_assignments = local_cpus
        .into_iter()
        .take(requested)
        .enumerate()
        .map(|(queue_id, logical_cpu)| RxQueueAssignment {
            queue_id: u16::try_from(queue_id).unwrap_or(u16::MAX),
            logical_cpu,
        })
        .collect();
    let plan = QueuePlan {
        numa_node: nic_numa_node,
        rx_queues,
        tx_queues,
        rx_assignments,
    };
    plan.validate()?;
    Ok(plan)
}

/// Mbuf pool sizing 所需的實際 pipeline 參數。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MbufPoolSizing {
    /// RX queue 數量。
    pub rx_queues: u32,
    /// 每個 RX queue descriptors。
    pub rx_descriptors_per_queue: u32,
    /// TX queue 數量。
    pub tx_queues: u32,
    /// 每個 TX queue descriptors。
    pub tx_descriptors_per_queue: u32,
    /// Worker 每次處理的最大 burst。
    pub burst_size: u32,
    /// 同時在 pipeline 中的 burst 數量。
    pub pipeline_depth: u32,
    /// Capture branch 最多持有的 packet buffers。
    pub capture_buffers: u64,
    /// 額外安全容量，以 mbuf 數量表示。
    pub safety_margin: u64,
}

/// 依 descriptors、queue、burst、pipeline、capture 與 safety margin 計算 pool 大小。
///
/// # Errors
///
/// 任一必要參數為零或整數運算溢位時回傳錯誤。
pub fn required_mbufs(sizing: MbufPoolSizing) -> Result<u64, NetToolError> {
    if sizing.rx_queues == 0
        || sizing.rx_descriptors_per_queue == 0
        || sizing.tx_queues == 0
        || sizing.tx_descriptors_per_queue == 0
        || sizing.burst_size == 0
        || sizing.pipeline_depth == 0
        || sizing.safety_margin == 0
    {
        return Err(invalid("mbuf sizing inputs must be non-zero"));
    }
    let rx = u64::from(sizing.rx_queues)
        .checked_mul(u64::from(sizing.rx_descriptors_per_queue))
        .ok_or_else(|| invalid("RX descriptor capacity overflow"))?;
    let tx = u64::from(sizing.tx_queues)
        .checked_mul(u64::from(sizing.tx_descriptors_per_queue))
        .ok_or_else(|| invalid("TX descriptor capacity overflow"))?;
    let in_flight = u64::from(sizing.rx_queues.max(sizing.tx_queues))
        .checked_mul(u64::from(sizing.burst_size))
        .and_then(|value| value.checked_mul(u64::from(sizing.pipeline_depth)))
        .ok_or_else(|| invalid("pipeline capacity overflow"))?;
    rx.checked_add(tx)
        .and_then(|value| value.checked_add(in_flight))
        .and_then(|value| value.checked_add(sizing.capture_buffers))
        .and_then(|value| value.checked_add(sizing.safety_margin))
        .ok_or_else(|| invalid("mbuf pool capacity overflow"))
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{
        DataPlaneCpu, MbufPoolSizing, NicQueueCapacity, QueueSelection, plan_queues, required_mbufs,
    };

    fn cpus() -> Vec<DataPlaneCpu> {
        vec![
            DataPlaneCpu {
                logical_id: 8,
                numa_node: 0,
            },
            DataPlaneCpu {
                logical_id: 4,
                numa_node: 0,
            },
            DataPlaneCpu {
                logical_id: 6,
                numa_node: 0,
            },
            DataPlaneCpu {
                logical_id: 20,
                numa_node: 1,
            },
        ]
    }

    #[test]
    fn auto_plan_uses_smallest_real_capacity_and_stable_cpu_order() {
        let plan = plan_queues(
            0,
            NicQueueCapacity {
                receive: 16,
                transmit: 8,
            },
            &cpus(),
            4,
            QueueSelection::Auto,
        )
        .expect("plan");
        assert_eq!(plan.rx_queues, 3);
        assert_eq!(plan.tx_queues, 3);
        assert_eq!(
            plan.rx_assignments
                .iter()
                .map(|item| item.logical_cpu)
                .collect::<Vec<_>>(),
            vec![4, 6, 8]
        );
    }

    #[test]
    fn explicit_plan_rejects_cross_numa_or_excess_queues() {
        let capacity = NicQueueCapacity {
            receive: 16,
            transmit: 16,
        };
        assert!(plan_queues(0, capacity, &cpus(), 16, QueueSelection::Explicit(4)).is_err());
        assert!(plan_queues(2, capacity, &cpus(), 16, QueueSelection::Explicit(1)).is_err());
    }

    #[test]
    fn duplicate_cpu_cannot_own_multiple_queues() {
        let duplicated = vec![
            DataPlaneCpu {
                logical_id: 4,
                numa_node: 0,
            },
            DataPlaneCpu {
                logical_id: 4,
                numa_node: 0,
            },
        ];
        assert!(
            plan_queues(
                0,
                NicQueueCapacity {
                    receive: 2,
                    transmit: 2,
                },
                &duplicated,
                2,
                QueueSelection::Auto,
            )
            .is_err()
        );
    }

    #[test]
    fn queue_plan_validation_rejects_non_contiguous_ownership() {
        let mut plan = plan_queues(
            0,
            NicQueueCapacity {
                receive: 2,
                transmit: 2,
            },
            &cpus(),
            2,
            QueueSelection::Explicit(2),
        )
        .expect("plan");
        plan.rx_assignments[1].queue_id = 3;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn sizes_pool_from_every_required_component() {
        let count = required_mbufs(MbufPoolSizing {
            rx_queues: 4,
            rx_descriptors_per_queue: 1024,
            tx_queues: 4,
            tx_descriptors_per_queue: 512,
            burst_size: 64,
            pipeline_depth: 2,
            capture_buffers: 2048,
            safety_margin: 1024,
        })
        .expect("size");
        assert_eq!(count, 9_728);
    }

    #[test]
    fn refuses_zero_or_overflowing_inputs() {
        let mut sizing = MbufPoolSizing {
            rx_queues: 1,
            rx_descriptors_per_queue: 1,
            tx_queues: 1,
            tx_descriptors_per_queue: 1,
            burst_size: 1,
            pipeline_depth: 1,
            capture_buffers: 0,
            safety_margin: 1,
        };
        sizing.burst_size = 0;
        assert!(required_mbufs(sizing).is_err());
        sizing.burst_size = u32::MAX;
        sizing.pipeline_depth = u32::MAX;
        sizing.rx_queues = u32::MAX;
        assert!(required_mbufs(sizing).is_err());
    }
}
