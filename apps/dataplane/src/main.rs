//! `NetTool` 高速資料平面程序的 P0 命令列入口。

#![forbid(unsafe_code)]

#[cfg(feature = "ffi-api")]
use nettool_backend_dpdk::{
    DataPlaneCpu, MbufPoolSizing, NicQueueCapacity, QueuePlan, QueueSelection, plan_queues,
    required_mbufs,
};
use nettool_backend_dpdk::{
    DpdkPreflightRequest, PreflightSeverity, detect_management_pci_address, evaluate_preflight,
    probe_environment,
};
use nettool_backend_pcap::CaptureFileSource;
use nettool_domain::{NicProbe, ProbeReport};
use nettool_error::{ErrorCode, NetToolError};
use nettool_packet::{
    AnalysisCoverage, PacketFilter, PacketWorker, PacketWorkerConfiguration, StopToken,
    WorkerRunResult,
};
#[cfg(feature = "ffi-api")]
use nettool_packet::{
    CaptureFormat, CaptureMode, CaptureQueue, CaptureRotation, GeneratorNetwork,
    GeneratorTransport, IpRange, PortRange, RawGeneratorProfile, RotatingCaptureWriter,
};
use std::env;
use std::fmt::Write as _;
use std::net::IpAddr;
#[cfg(feature = "ffi-api")]
use std::net::Ipv4Addr;
use std::process::ExitCode;
#[cfg(feature = "ffi-api")]
use std::thread;
#[cfg(feature = "ffi-api")]
use std::time::Instant;

#[derive(Clone, Copy)]
enum Output {
    Human,
    Json,
}

enum Command {
    Probe(Output),
    RxDpdk {
        interface: String,
    },
    TxDpdk {
        interface: String,
        frame_size: u16,
        packets: u64,
    },
    CaptureDpdk {
        interface: String,
        directory: String,
        bursts: u64,
        filter: PacketFilter,
    },
    Analyze {
        input: String,
        sample_one_in: Option<u32>,
        output: Output,
    },
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", error_json(&error));
            ExitCode::from(2)
        }
    }
}

fn run(args: impl Iterator<Item = String>) -> Result<String, NetToolError> {
    match parse_args(args)? {
        Command::Probe(output) => {
            let report = probe_environment()?;
            Ok(match output {
                Output::Human => human_report(&report),
                Output::Json => json_report(&report),
            })
        }
        Command::RxDpdk { interface } => run_dpdk_rx(&interface),
        Command::TxDpdk {
            interface,
            frame_size,
            packets,
        } => run_dpdk_tx(&interface, frame_size, packets),
        Command::CaptureDpdk {
            interface,
            directory,
            bursts,
            filter,
        } => run_dpdk_capture(&interface, &directory, bursts, filter),
        Command::Analyze {
            input,
            sample_one_in,
            output,
        } => run_offline_analysis(&input, sample_one_in, output),
    }
}

#[allow(clippy::too_many_lines)]
fn parse_args(args: impl Iterator<Item = String>) -> Result<Command, NetToolError> {
    let args: Vec<_> = args.collect();
    if args.first().is_some_and(|command| command == "analyze") {
        return parse_analyze_args(&args[1..]);
    }
    if args.first().is_some_and(|command| command == "capture") {
        return parse_capture_args(&args[1..]);
    }
    match args.as_slice() {
        [command] if command == "probe" => Ok(Command::Probe(Output::Human)),
        [command, flag, value] if command == "probe" && flag == "--output" && value == "json" => {
            Ok(Command::Probe(Output::Json))
        }
        [command, backend_flag, backend, interface_flag, interface]
            if command == "rx"
                && backend_flag == "--backend"
                && backend == "dpdk"
                && interface_flag == "--interface" =>
        {
            Ok(Command::RxDpdk {
                interface: interface.clone(),
            })
        }
        [
            command,
            backend_flag,
            backend,
            interface_flag,
            interface,
            output_flag,
            output,
        ] if command == "rx"
            && backend_flag == "--backend"
            && backend == "dpdk"
            && interface_flag == "--interface"
            && output_flag == "--output"
            && output == "json" =>
        {
            Ok(Command::RxDpdk {
                interface: interface.clone(),
            })
        }
        [
            command,
            backend_flag,
            backend,
            interface_flag,
            interface,
            frame_flag,
            frame_size,
            packets_flag,
            packets,
        ] if command == "tx"
            && backend_flag == "--backend"
            && backend == "dpdk"
            && interface_flag == "--interface"
            && frame_flag == "--frame-size"
            && packets_flag == "--packets" =>
        {
            let frame_size = frame_size.parse::<u16>().map_err(|_| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "frame size must be an integer",
                    false,
                )
            })?;
            let packets = packets.parse::<u64>().map_err(|_| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "packet count must be an integer",
                    false,
                )
            })?;
            if !(64..=9_018).contains(&frame_size) || packets == 0 {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "frame size must be 64..=9018 and packet count must be non-zero",
                    false,
                ));
            }
            Ok(Command::TxDpdk {
                interface: interface.clone(),
                frame_size,
                packets,
            })
        }
        _ => Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "usage: nettool-dataplane <probe [--output json] | rx --backend dpdk --interface <pci-address> [--output json] | tx --backend dpdk --interface <pci-address> --frame-size <64..9018> --packets <n> | capture --backend dpdk --interface <pci-address> --output <directory> --bursts <n> | analyze --input <capture> [--sample-one-in <n>] [--output json]>",
            false,
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn parse_capture_args(arguments: &[String]) -> Result<Command, NetToolError> {
    let mut backend = None;
    let mut interface = None;
    let mut directory = None;
    let mut bursts = None;
    let mut filter = PacketFilter::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments.get(index + 1).ok_or_else(|| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("missing value for {flag}"),
                false,
            )
        })?;
        match flag {
            "--backend" if backend.is_none() && value == "dpdk" => backend = Some(value),
            "--interface" if interface.is_none() => interface = Some(value),
            "--output" if directory.is_none() => directory = Some(value),
            "--bursts" if bursts.is_none() => {
                let parsed = value.parse::<u64>().map_err(|_| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "burst count must be an integer",
                        false,
                    )
                })?;
                if parsed == 0 {
                    return Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "burst count must be non-zero",
                        false,
                    ));
                }
                bursts = Some(parsed);
            }
            "--protocol" if filter.protocol.is_none() => {
                filter.protocol = Some(parse_protocol(value)?);
            }
            "--source-ip" if filter.source_ip.is_none() => {
                filter.source_ip = Some(value.parse::<IpAddr>().map_err(|_| {
                    NetToolError::new(ErrorCode::InvalidArgument, "source IP is invalid", false)
                })?);
            }
            "--destination-ip" if filter.destination_ip.is_none() => {
                filter.destination_ip = Some(value.parse::<IpAddr>().map_err(|_| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "destination IP is invalid",
                        false,
                    )
                })?);
            }
            "--source-port" if filter.source_port.is_none() => {
                filter.source_port = Some(parse_port(value, "source port")?);
            }
            "--destination-port" if filter.destination_port.is_none() => {
                filter.destination_port = Some(parse_port(value, "destination port")?);
            }
            _ => {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown or duplicate capture option: {flag}"),
                    false,
                ));
            }
        }
        index += 2;
    }
    if backend.is_none() {
        return Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "capture requires --backend dpdk",
            false,
        ));
    }
    Ok(Command::CaptureDpdk {
        interface: interface
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "capture requires --interface",
                    false,
                )
            })?
            .clone(),
        directory: directory
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "capture requires --output",
                    false,
                )
            })?
            .clone(),
        bursts: bursts.ok_or_else(|| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "capture requires --bursts",
                false,
            )
        })?,
        filter,
    })
}

fn parse_protocol(value: &str) -> Result<u8, NetToolError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" => Ok(58),
        _ => value.parse::<u8>().map_err(|_| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "protocol must be tcp, udp, icmp, icmpv6, or an IP protocol number",
                false,
            )
        }),
    }
}

fn parse_port(value: &str, name: &str) -> Result<u16, NetToolError> {
    value.parse::<u16>().map_err(|_| {
        NetToolError::new(
            ErrorCode::InvalidArgument,
            format!("{name} must be an integer between 0 and 65535"),
            false,
        )
    })
}

fn parse_analyze_args(arguments: &[String]) -> Result<Command, NetToolError> {
    let mut input = None;
    let mut sample_one_in = None;
    let mut output = Output::Human;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let value = arguments.get(index + 1).ok_or_else(|| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                format!("missing value for {flag}"),
                false,
            )
        })?;
        match flag.as_str() {
            "--input" if input.is_none() => input = Some(value.clone()),
            "--sample-one-in" if sample_one_in.is_none() => {
                let ratio = value.parse::<u32>().map_err(|_| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "sample ratio must be an unsigned integer",
                        false,
                    )
                })?;
                if ratio == 0 {
                    return Err(NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "sample ratio must be greater than zero",
                        false,
                    ));
                }
                sample_one_in = Some(ratio);
            }
            "--output" if value == "json" && matches!(output, Output::Human) => {
                output = Output::Json;
            }
            _ => {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown or duplicate analyze option: {flag}"),
                    false,
                ));
            }
        }
        index += 2;
    }
    Ok(Command::Analyze {
        input: input.ok_or_else(|| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "analyze requires --input <capture>",
                false,
            )
        })?,
        sample_one_in,
        output,
    })
}

fn run_offline_analysis(
    input: &str,
    sample_one_in: Option<u32>,
    output: Output,
) -> Result<String, NetToolError> {
    let coverage = sample_one_in.map_or(AnalysisCoverage::Full, |one_in| {
        AnalysisCoverage::Sampled { one_in }
    });
    let mut source = CaptureFileSource::open(input)?;
    let mut worker = PacketWorker::new(
        PacketWorkerConfiguration {
            maximum_flows: 1_000_000,
            flow_idle_timeout_nanoseconds: 60_000_000_000,
            analysis_coverage: coverage,
        },
        None,
    )?;
    let result = worker.run_bursts(&mut source, u64::MAX, &StopToken::new())?;
    Ok(match output {
        Output::Human => human_analysis(&result),
        Output::Json => json_analysis(input, &result),
    })
}

fn human_analysis(result: &WorkerRunResult) -> String {
    let coverage = match result.analysis_coverage {
        AnalysisCoverage::Full => "Full Analysis".to_owned(),
        AnalysisCoverage::Sampled { one_in } => {
            format!("Sampled Analysis (1 in {one_in})")
        }
    };
    format!(
        "Coverage: {coverage}\nPackets: {}\nBytes: {}\nIPv4: {}\nIPv6: {}\nTCP: {}\nUDP: {}\nICMP: {}\nOther: {}\nFlows: {}\nRetransmissions: {}\nParse Errors: {}\nSampled Out: {}",
        result.statistics.rx_packets,
        result.statistics.rx_bytes,
        result.statistics.ipv4_packets,
        result.statistics.ipv6_packets,
        result.statistics.tcp_packets,
        result.statistics.udp_packets,
        result.statistics.icmp_packets,
        result.statistics.other_packets,
        result.statistics.flows,
        result.statistics.retransmissions,
        result.statistics.parse_errors,
        result.statistics.sampled_out_packets,
    )
}

fn json_analysis(input: &str, result: &WorkerRunResult) -> String {
    let (coverage, sample_one_in) = match result.analysis_coverage {
        AnalysisCoverage::Full => ("full", None),
        AnalysisCoverage::Sampled { one_in } => ("sampled", Some(one_in)),
    };
    serde_json::json!({
        "schema_version": "1.0",
        "success": true,
        "backend": "offline_capture",
        "input": input,
        "analysis": {
            "coverage": coverage,
            "sample_one_in": sample_one_in,
        },
        "statistics": result.statistics,
    })
    .to_string()
}

fn run_dpdk_rx(interface: &str) -> Result<String, NetToolError> {
    let report = probe_environment()?;
    let nic_numa = report
        .nics
        .iter()
        .find(|nic| nic.pci_address.as_deref() == Some(interface))
        .and_then(|nic| nic.numa_node);
    let preflight = evaluate_preflight(
        &report,
        &DpdkPreflightRequest {
            pci_address: interface.to_owned(),
            management_pci_address: detect_management_pci_address(&report.nics),
            rx_queues: 1,
            tx_queues: 1,
            worker_numa_node: nic_numa,
            worker_cpus: vec![0],
            required_huge_pages: 1,
            certification_mode: false,
        },
    );
    if !preflight.can_run {
        let failures = preflight
            .checks
            .iter()
            .filter(|check| check.severity == PreflightSeverity::Fail)
            .map(|check| format!("{}: {}", check.id, check.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(NetToolError::new(
            ErrorCode::PreflightFailed,
            format!("DPDK RX preflight failed: {failures}"),
            false,
        ));
    }
    run_native_dpdk_rx(interface)
}

fn run_dpdk_tx(interface: &str, frame_size: u16, packets: u64) -> Result<String, NetToolError> {
    let report = probe_environment()?;
    let nic_numa = report
        .nics
        .iter()
        .find(|nic| nic.pci_address.as_deref() == Some(interface))
        .and_then(|nic| nic.numa_node);
    let preflight = evaluate_preflight(
        &report,
        &DpdkPreflightRequest {
            pci_address: interface.to_owned(),
            management_pci_address: detect_management_pci_address(&report.nics),
            rx_queues: 1,
            tx_queues: 1,
            worker_numa_node: nic_numa,
            worker_cpus: vec![0],
            required_huge_pages: 1,
            certification_mode: false,
        },
    );
    if !preflight.can_run {
        let failures = preflight
            .checks
            .iter()
            .filter(|check| check.severity == PreflightSeverity::Fail)
            .map(|check| format!("{}: {}", check.id, check.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(NetToolError::new(
            ErrorCode::PreflightFailed,
            format!("DPDK TX preflight failed: {failures}"),
            false,
        ));
    }
    run_native_dpdk_tx(interface, frame_size, packets)
}

fn run_dpdk_capture(
    interface: &str,
    directory: &str,
    bursts: u64,
    filter: PacketFilter,
) -> Result<String, NetToolError> {
    let report = probe_environment()?;
    let nic_numa = report
        .nics
        .iter()
        .find(|nic| nic.pci_address.as_deref() == Some(interface))
        .and_then(|nic| nic.numa_node);
    let preflight = evaluate_preflight(
        &report,
        &DpdkPreflightRequest {
            pci_address: interface.to_owned(),
            management_pci_address: detect_management_pci_address(&report.nics),
            rx_queues: 1,
            tx_queues: 1,
            worker_numa_node: nic_numa,
            worker_cpus: vec![0],
            required_huge_pages: 1,
            certification_mode: false,
        },
    );
    if !preflight.can_run {
        let failures = preflight
            .checks
            .iter()
            .filter(|check| check.severity == PreflightSeverity::Fail)
            .map(|check| format!("{}: {}", check.id, check.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(NetToolError::new(
            ErrorCode::PreflightFailed,
            format!("DPDK capture preflight failed: {failures}"),
            false,
        ));
    }
    run_native_dpdk_capture(interface, directory, bursts, filter)
}

#[cfg(not(feature = "ffi-api"))]
fn run_native_dpdk_rx(_interface: &str) -> Result<String, NetToolError> {
    Err(nettool_dpdk_safe::backend_not_built())
}

#[cfg(not(feature = "ffi-api"))]
fn run_native_dpdk_tx(
    _interface: &str,
    _frame_size: u16,
    _packets: u64,
) -> Result<String, NetToolError> {
    Err(nettool_dpdk_safe::backend_not_built())
}

#[cfg(not(feature = "ffi-api"))]
fn run_native_dpdk_capture(
    _interface: &str,
    _directory: &str,
    _bursts: u64,
    _filter: PacketFilter,
) -> Result<String, NetToolError> {
    Err(nettool_dpdk_safe::backend_not_built())
}

#[cfg(feature = "ffi-api")]
#[allow(clippy::too_many_lines, clippy::drop_non_drop)]
fn run_native_dpdk_capture(
    interface: &str,
    directory: &str,
    bursts: u64,
    filter: PacketFilter,
) -> Result<String, NetToolError> {
    use nettool_dpdk_safe::{Environment, MempoolConfiguration, PortConfiguration};

    let queue_plan = native_queue_plan(interface)?;
    #[cfg(target_os = "linux")]
    pin_native_worker(queue_plan.rx_assignments[0].logical_cpu)?;

    let environment = Environment::initialize(&[
        "nettool-dataplane".to_owned(),
        "--no-telemetry".to_owned(),
        "-a".to_owned(),
        interface.to_owned(),
    ])?;
    let port_id = environment.port_by_name(interface)?;
    let mbuf_count = required_mbufs(MbufPoolSizing {
        rx_queues: u32::from(queue_plan.rx_queues),
        rx_descriptors_per_queue: 1024,
        tx_queues: u32::from(queue_plan.tx_queues),
        tx_descriptors_per_queue: 1024,
        burst_size: 64,
        pipeline_depth: 1,
        capture_buffers: 4096,
        safety_margin: 1024,
    })?;
    let pool = environment.create_mempool(&MempoolConfiguration {
        name: format!("nettool_capture_{port_id}"),
        count: u32::try_from(mbuf_count).map_err(|_| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "DPDK mbuf pool size exceeds u32 capacity",
                false,
            )
        })?,
        cache_size: 256,
        data_room_size: 9_600,
        socket_id: 0,
    })?;
    let mut port = pool.configure_port(PortConfiguration {
        port_id,
        rx_queues: queue_plan.rx_queues,
        tx_queues: queue_plan.tx_queues,
        rx_descriptors: 1024,
        tx_descriptors: 1024,
        socket_id: 0,
    })?;
    port.start()?;
    let mut rx_queue = port.rx_queue(0, 64)?;
    let (capture, receiver) = CaptureQueue::bounded(4096, CaptureMode::FullPacket)?;
    let mut writer = RotatingCaptureWriter::create(
        directory,
        "capture",
        CaptureFormat::PcapNg,
        CaptureMode::FullPacket,
        interface,
        CaptureRotation {
            maximum_bytes: Some(1 << 30),
            maximum_duration: Some(std::time::Duration::from_secs(60)),
            file_count: 4,
        },
    )
    .map_err(|error| capture_io_error(&error))?;
    let writer_thread = thread::spawn(move || -> Result<(), NetToolError> {
        while let Some(record) = receiver.receive() {
            writer
                .write_record(&record)
                .map_err(|error| capture_io_error(&error))?;
        }
        writer.flush().map_err(|error| capture_io_error(&error))
    });
    let mut source = NativeDpdkSource {
        queue: &mut rx_queue,
        started_at: Instant::now(),
    };
    let mut worker = PacketWorker::new_with_filter(
        PacketWorkerConfiguration {
            maximum_flows: 1_000_000,
            flow_idle_timeout_nanoseconds: 60_000_000_000,
            analysis_coverage: AnalysisCoverage::Full,
        },
        Some(capture),
        Some(filter),
    )?;
    let result = worker.run_bursts(&mut source, bursts, &StopToken::new())?;
    drop(worker);
    drop(source);
    drop(rx_queue);
    let hardware = port.stats()?;
    let xstats = port.xstats()?;
    let writer_result = writer_thread.join().map_err(|_| {
        NetToolError::new(
            ErrorCode::PreflightFailed,
            "capture writer thread panicked",
            false,
        )
    })?;
    writer_result?;
    Ok(serde_json::json!({
        "schema_version": "1.0",
        "success": true,
        "backend": "dpdk",
        "interface": interface,
        "bursts_requested": bursts,
        "statistics": result.statistics,
        "capture_directory": directory,
        "format": "pcapng",
        "capture_mode": "full_packet",
        "hardware": hardware_stats_json(hardware, &xstats),
    })
    .to_string())
}

#[cfg(feature = "ffi-api")]
fn capture_io_error(error: &std::io::Error) -> NetToolError {
    NetToolError::new(
        ErrorCode::PreflightFailed,
        format!("capture writer I/O failed: {error}"),
        true,
    )
}

#[cfg(all(feature = "ffi-api", target_os = "linux"))]
fn pin_native_worker(logical_cpu: u32) -> Result<(), NetToolError> {
    let cpu_set = nettool_platform_affinity::CpuSet::single(logical_cpu).map_err(|error| {
        NetToolError::new(
            ErrorCode::PreflightFailed,
            format!("native DPDK worker CPU set is invalid: {error}"),
            false,
        )
    })?;
    nettool_platform_affinity::pin_current_thread(&cpu_set).map_err(|error| {
        NetToolError::new(
            ErrorCode::PreflightFailed,
            format!("native DPDK worker affinity failed: {error}"),
            true,
        )
    })
}

#[cfg(feature = "ffi-api")]
fn native_queue_plan(interface: &str) -> Result<QueuePlan, NetToolError> {
    let report = probe_environment()?;
    let nic = report
        .nics
        .iter()
        .find(|nic| nic.name == interface || nic.pci_address.as_deref() == Some(interface))
        .ok_or_else(|| {
            NetToolError::new(
                ErrorCode::PreflightFailed,
                "native DPDK interface is absent from the latest capability snapshot",
                false,
            )
        })?;
    let numa_node = nic.numa_node.ok_or_else(|| {
        NetToolError::new(
            ErrorCode::PreflightFailed,
            "native DPDK interface NUMA node is unknown",
            false,
        )
    })?;
    let receive = u16::try_from(nic.rx_queues.unwrap_or_default()).map_err(|_| {
        NetToolError::new(
            ErrorCode::PreflightFailed,
            "native DPDK RX queue count exceeds planner bounds",
            false,
        )
    })?;
    let transmit = u16::try_from(nic.tx_queues.unwrap_or_default()).map_err(|_| {
        NetToolError::new(
            ErrorCode::PreflightFailed,
            "native DPDK TX queue count exceeds planner bounds",
            false,
        )
    })?;
    let plan = plan_queues(
        numa_node,
        NicQueueCapacity { receive, transmit },
        &[DataPlaneCpu {
            logical_id: 0,
            numa_node,
        }],
        1,
        QueueSelection::Auto,
    )?;
    plan.validate()?;
    Ok(plan)
}

#[cfg(feature = "ffi-api")]
#[allow(clippy::drop_non_drop)]
fn run_native_dpdk_rx(interface: &str) -> Result<String, NetToolError> {
    use nettool_dpdk_safe::{Environment, MempoolConfiguration, PortConfiguration};

    let queue_plan = native_queue_plan(interface)?;
    #[cfg(target_os = "linux")]
    pin_native_worker(queue_plan.rx_assignments[0].logical_cpu)?;

    let arguments = vec![
        "nettool-dataplane".to_owned(),
        "--no-telemetry".to_owned(),
        "-a".to_owned(),
        interface.to_owned(),
    ];
    let environment = Environment::initialize(&arguments)?;
    let port_id = environment.port_by_name(interface)?;
    let mbuf_count = required_mbufs(MbufPoolSizing {
        rx_queues: u32::from(queue_plan.rx_queues),
        rx_descriptors_per_queue: 1024,
        tx_queues: u32::from(queue_plan.tx_queues),
        tx_descriptors_per_queue: 1024,
        burst_size: 64,
        pipeline_depth: 1,
        capture_buffers: 0,
        safety_margin: 1024,
    })?;
    let mbuf_count = u32::try_from(mbuf_count).map_err(|_| {
        NetToolError::new(
            ErrorCode::InvalidArgument,
            "DPDK mbuf pool size exceeds u32 capacity",
            false,
        )
    })?;
    let pool = environment.create_mempool(&MempoolConfiguration {
        name: format!("nettool_rx_{port_id}"),
        count: mbuf_count,
        cache_size: 256,
        data_room_size: 9_600,
        socket_id: 0,
    })?;
    let mut port = pool.configure_port(PortConfiguration {
        port_id,
        rx_queues: queue_plan.rx_queues,
        tx_queues: queue_plan.tx_queues,
        rx_descriptors: 1024,
        tx_descriptors: 1024,
        socket_id: 0,
    })?;
    port.start()?;
    let mut queue = port.rx_queue(0, 64)?;
    let mut source = NativeDpdkSource {
        queue: &mut queue,
        started_at: Instant::now(),
    };
    let mut worker = PacketWorker::new(
        PacketWorkerConfiguration {
            maximum_flows: 1_000_000,
            flow_idle_timeout_nanoseconds: 60_000_000_000,
            analysis_coverage: AnalysisCoverage::Full,
        },
        None,
    )?;
    let result = worker.run_bursts(&mut source, u64::MAX, &StopToken::new())?;
    drop(source);
    drop(queue);
    let hardware = port.stats()?;
    let xstats = port.xstats()?;
    Ok(json_live_analysis(interface, &result, hardware, &xstats))
}

#[cfg(feature = "ffi-api")]
fn run_native_dpdk_tx(
    interface: &str,
    frame_size: u16,
    packets: u64,
) -> Result<String, NetToolError> {
    use nettool_dpdk_safe::{Environment, MempoolConfiguration, PortConfiguration};

    let queue_plan = native_queue_plan(interface)?;
    #[cfg(target_os = "linux")]
    pin_native_worker(queue_plan.rx_assignments[0].logical_cpu)?;

    let profile = RawGeneratorProfile {
        ethernet_size: frame_size,
        network: GeneratorNetwork::Ipv4,
        transport: GeneratorTransport::Udp,
        source_ips: IpRange {
            start: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            end: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        },
        destination_ips: IpRange {
            start: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            end: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        },
        source_ports: PortRange {
            start: 10_000,
            end: 10_000,
        },
        destination_ports: PortRange {
            start: 20_000,
            end: 20_000,
        },
        flow_count: 1,
        packet_rate: packets,
    };
    let template = profile.template_bytes()?;
    let environment = Environment::initialize(&[
        "nettool-dataplane".to_owned(),
        "--no-telemetry".to_owned(),
        "-a".to_owned(),
        interface.to_owned(),
    ])?;
    let port_id = environment.port_by_name(interface)?;
    let mbuf_count = required_mbufs(MbufPoolSizing {
        rx_queues: u32::from(queue_plan.rx_queues),
        rx_descriptors_per_queue: 1024,
        tx_queues: u32::from(queue_plan.tx_queues),
        tx_descriptors_per_queue: 1024,
        burst_size: 64,
        pipeline_depth: 1,
        capture_buffers: 0,
        safety_margin: 1024,
    })?;
    let pool = environment.create_mempool(&MempoolConfiguration {
        name: format!("nettool_tx_{port_id}"),
        count: u32::try_from(mbuf_count).map_err(|_| {
            NetToolError::new(
                ErrorCode::InvalidArgument,
                "DPDK mbuf pool size exceeds u32 capacity",
                false,
            )
        })?,
        cache_size: 256,
        data_room_size: 9_600,
        socket_id: 0,
    })?;
    let mut port = pool.configure_port(PortConfiguration {
        port_id,
        rx_queues: queue_plan.rx_queues,
        tx_queues: queue_plan.tx_queues,
        rx_descriptors: 1024,
        tx_descriptors: 1024,
        socket_id: 0,
    })?;
    port.start()?;
    let mut queue = port.tx_queue(0, &pool)?;
    let mut sent = 0_u64;
    while sent < packets {
        let requested = u16::try_from((packets - sent).min(64)).unwrap_or(64);
        let accepted = u64::from(queue.send_template_burst(&template, requested)?);
        if accepted == 0 {
            return Err(NetToolError::new(
                ErrorCode::PreflightFailed,
                "DPDK TX made no forward progress",
                true,
            ));
        }
        sent = sent.saturating_add(accepted);
    }
    drop(queue);
    let hardware = port.stats()?;
    let xstats = port.xstats()?;
    Ok(serde_json::json!({
        "backend": "dpdk",
        "interface": interface,
        "frame_size": frame_size,
        "packets_requested": packets,
        "packets_sent": sent,
        "unsent_packets": 0,
        "hardware": hardware_stats_json(hardware, &xstats),
    })
    .to_string())
}

#[cfg(feature = "ffi-api")]
struct NativeDpdkSource<'queue, 'port> {
    queue: &'queue mut nettool_dpdk_safe::RxQueue<'port>,
    started_at: Instant,
}

#[cfg(feature = "ffi-api")]
impl nettool_packet::BurstSource for NativeDpdkSource<'_, '_> {
    fn receive_burst(
        &mut self,
        mut consumer: impl FnMut(nettool_packet::PacketView<'_>),
    ) -> Result<usize, NetToolError> {
        let timestamp = u64::try_from(self.started_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.queue.receive_burst(|packet| {
            consumer(nettool_packet::PacketView {
                bytes: packet.bytes,
                timestamp_nanoseconds: timestamp,
                wire_length: packet.metadata.packet_length,
                queue_id: packet.metadata.queue_id,
            });
        })
    }
}

#[cfg(feature = "ffi-api")]
fn json_live_analysis(
    interface: &str,
    result: &WorkerRunResult,
    hardware: nettool_dpdk_safe::PortStats,
    xstats: &[nettool_dpdk_safe::XStat],
) -> String {
    serde_json::json!({
        "schema_version": "1.0",
        "success": true,
        "backend": "dpdk",
        "interface": interface,
        "analysis": { "coverage": "full" },
        "statistics": result.statistics,
        "hardware": hardware_stats_json(hardware, xstats),
    })
    .to_string()
}

#[cfg(feature = "ffi-api")]
fn hardware_stats_json(
    stats: nettool_dpdk_safe::PortStats,
    xstats: &[nettool_dpdk_safe::XStat],
) -> serde_json::Value {
    let xstats = xstats
        .iter()
        .map(|stat| serde_json::json!({"name": stat.name, "value": stat.value}))
        .collect::<Vec<_>>();
    serde_json::json!({
        "source": "dpdk_rte_eth_stats",
        "received_packets": stats.received_packets,
        "transmitted_packets": stats.transmitted_packets,
        "received_bytes": stats.received_bytes,
        "transmitted_bytes": stats.transmitted_bytes,
        "missed_packets": stats.missed_packets,
        "receive_errors": stats.receive_errors,
        "transmit_errors": stats.transmit_errors,
        "rx_mbuf_failures": stats.rx_mbuf_failures,
        "xstats_source": "dpdk_rte_eth_xstats",
        "xstats": xstats,
    })
}

fn human_report(report: &ProbeReport) -> String {
    let mut lines = vec![
        format!("Platform: {}", report.platform.as_str()),
        format!("CPU: {} logical CPUs", report.logical_cpus),
        format!("NUMA: {}", optional(report.numa_nodes)),
        format!(
            "Huge Pages: total={}, free={}, size_kib={}",
            optional(report.huge_pages_total),
            optional(report.huge_pages_free),
            optional(report.huge_page_size_kib)
        ),
        format!("DPDK Capability: {}", yes_no(report.dpdk_capable)),
        format!("AF_XDP Capability: {}", yes_no(report.af_xdp_capable)),
        format!(
            "AF_XDP Zero Copy Capability: {}",
            yes_no(report.af_xdp_zero_copy_capable)
        ),
    ];
    if report.nics.is_empty() {
        lines.push("NIC: none detected".to_owned());
    }
    for nic in &report.nics {
        lines.push(human_nic(nic));
    }
    for warning in &report.warnings {
        lines.push(format!("Warning: {warning}"));
    }
    lines.join("\n")
}

fn human_nic(nic: &NicProbe) -> String {
    format!(
        "NIC: {} | PCI Address: {} | Driver: {} | Link Speed: {} Mbps | RX Queues: {} | TX Queues: {} | NUMA: {}",
        nic.name,
        optional_ref(nic.pci_address.as_deref()),
        optional_ref(nic.driver.as_deref()),
        optional(nic.link_speed_mbps),
        optional(nic.rx_queues),
        optional(nic.tx_queues),
        optional(nic.numa_node)
    )
}

fn json_report(report: &ProbeReport) -> String {
    let nics = report
        .nics
        .iter()
        .map(json_nic)
        .collect::<Vec<_>>()
        .join(",");
    let warnings = report
        .warnings
        .iter()
        .map(|value| quote(value))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema_version\":{},\"platform\":{},\"cpu\":{{\"logical_count\":{}}},\"numa\":{{\"node_count\":{}}},\"huge_pages\":{{\"total\":{},\"free\":{},\"size_kib\":{}}},\"nics\":[{}],\"dpdk_capable\":{},\"af_xdp_capable\":{},\"af_xdp_zero_copy_capable\":{},\"warnings\":[{}]}}",
        quote(report.schema_version),
        quote(report.platform.as_str()),
        report.logical_cpus,
        json_optional(report.numa_nodes),
        json_optional(report.huge_pages_total),
        json_optional(report.huge_pages_free),
        json_optional(report.huge_page_size_kib),
        nics,
        report.dpdk_capable,
        report.af_xdp_capable,
        report.af_xdp_zero_copy_capable,
        warnings
    )
}

fn json_nic(nic: &NicProbe) -> String {
    format!(
        "{{\"name\":{},\"pci_address\":{},\"driver\":{},\"link_speed_mbps\":{},\"rx_queues\":{},\"tx_queues\":{},\"numa_node\":{}}}",
        quote(&nic.name),
        json_string(nic.pci_address.as_deref()),
        json_string(nic.driver.as_deref()),
        json_optional(nic.link_speed_mbps),
        json_optional(nic.rx_queues),
        json_optional(nic.tx_queues),
        json_optional(nic.numa_node)
    )
}

fn error_json(error: &NetToolError) -> String {
    format!(
        "{{\"schema_version\":\"1.0\",\"success\":false,\"error\":{{\"code\":{},\"message\":{},\"retryable\":{}}}}}",
        quote(error.code.as_str()),
        quote(&error.message),
        error.retryable
    )
}

fn quote(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            value if value.is_control() => {
                // 寫入 String 不會發生 fmt I/O 錯誤，因此不需將不可能失敗的結果升級為 CLI 錯誤。
                let _ = write!(result, "\\u{:04x}", u32::from(value));
            }
            value => result.push(value),
        }
    }
    result.push('\"');
    result
}

fn json_optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}
fn json_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), quote)
}
fn optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}
fn optional_ref(value: Option<&str>) -> &str {
    value.unwrap_or("unknown")
}
const fn yes_no(value: bool) -> &'static str {
    if value { "available" } else { "unavailable" }
}

#[cfg(test)]
mod tests {
    use super::{Command, Output, parse_args, quote, run};
    use std::fs;
    #[test]
    fn accepts_json_probe_contract() {
        assert!(parse_args(["probe", "--output", "json"].into_iter().map(str::to_owned)).is_ok());
    }
    #[test]
    fn escapes_machine_output() {
        assert_eq!(quote("a\"b\n"), "\"a\\\"b\\n\"");
    }
    #[test]
    fn accepts_required_dpdk_rx_command() {
        assert!(
            matches!(parse_args(["rx", "--backend", "dpdk", "--interface", "0000:01:00.0"].into_iter().map(str::to_owned)), Ok(Command::RxDpdk { interface }) if interface == "0000:01:00.0")
        );
    }

    #[test]
    fn accepts_bounded_dpdk_tx_command() {
        assert!(matches!(
            parse_args(
                [
                    "tx",
                    "--backend",
                    "dpdk",
                    "--interface",
                    "0000:01:00.0",
                    "--frame-size",
                    "64",
                    "--packets",
                    "128"
                ]
                .into_iter()
                .map(str::to_owned)
            ),
            Ok(Command::TxDpdk { interface, frame_size: 64, packets: 128 })
                if interface == "0000:01:00.0"
        ));
        assert!(
            parse_args(
                [
                    "tx",
                    "--backend",
                    "dpdk",
                    "--interface",
                    "0000:01:00.0",
                    "--frame-size",
                    "63",
                    "--packets",
                    "1"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_bounded_dpdk_capture_command() {
        assert!(matches!(
            parse_args(
                [
                    "capture",
                    "--backend",
                    "dpdk",
                    "--interface",
                    "0000:01:00.0",
                    "--output",
                    "/tmp/capture",
                    "--bursts",
                    "8"
                ]
                .into_iter()
                .map(str::to_owned)
            ),
            Ok(Command::CaptureDpdk { interface, directory, bursts: 8, .. })
                if interface == "0000:01:00.0" && directory == "/tmp/capture"
        ));
        assert!(
            parse_args(
                [
                    "capture",
                    "--backend",
                    "dpdk",
                    "--interface",
                    "0000:01:00.0",
                    "--output",
                    "/tmp/capture",
                    "--bursts",
                    "0"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_capture_filters() {
        let parsed = parse_args(
            [
                "capture",
                "--backend",
                "dpdk",
                "--interface",
                "0000:01:00.0",
                "--output",
                "/tmp/capture",
                "--bursts",
                "8",
                "--protocol",
                "udp",
                "--source-ip",
                "192.0.2.1",
                "--destination-port",
                "443",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("capture filters");
        assert!(matches!(
            parsed,
            Command::CaptureDpdk { filter, .. }
                if filter.protocol == Some(17)
                    && filter.source_ip == Some("192.0.2.1".parse().expect("ip"))
                    && filter.destination_port == Some(443)
        ));
    }

    #[test]
    fn accepts_offline_analysis_and_rejects_zero_sampling() {
        assert!(matches!(
            parse_args(
                ["analyze", "--input", "capture.pcap", "--sample-one-in", "10", "--output", "json"]
                    .into_iter()
                    .map(str::to_owned)
            ),
            Ok(Command::Analyze { input, sample_one_in: Some(10), output: Output::Json }) if input == "capture.pcap"
        ));
        assert!(
            parse_args(
                ["analyze", "--input", "capture.pcap", "--sample-one-in", "0"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
    }

    #[test]
    fn analyzes_real_pcap_through_worker() {
        let path = std::env::temp_dir().join(format!(
            "nettool-dataplane-analysis-{}.pcap",
            std::process::id()
        ));
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2_3c4d_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        fs::write(&path, bytes).expect("fixture");
        let output = run([
            "analyze",
            "--input",
            path.to_str().expect("UTF-8 path"),
            "--output",
            "json",
        ]
        .into_iter()
        .map(str::to_owned))
        .expect("analysis");
        let output: serde_json::Value = serde_json::from_str(&output).expect("JSON");
        assert_eq!(output["statistics"]["rx_packets"], 1);
        assert_eq!(output["statistics"]["parse_errors"], 1);
        let _ = fs::remove_file(path);
    }
}
