#[allow(clippy::wildcard_imports)]
use super::*;

impl<R> MacosNetworkStateReader<R> {
    /// 建立 reader；實際命令由注入的 runner 執行，方便平台測試與 sandbox 驗證。
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: CommandRunner> PlatformStateReader for MacosNetworkStateReader<R> {
    fn read_state(&mut self, interface_id: &str) -> Result<NetworkDesiredState, NetToolError> {
        validate_interface(interface_id)?;
        let info = self.query(interface_id, ["-getinfo"])?;
        let v6_info = self.query(interface_id, ["-getv6info"])?;
        let dns_info = self.query(interface_id, ["-getdnsservers"])?;
        let mtu_info = self.query(interface_id, ["-getMTU"])?;
        parse_macos_state(&info, &v6_info, &dns_info, &mtu_info)
    }
}

impl<R: CommandRunner> MacosNetworkStateReader<R> {
    fn query<const N: usize>(
        &mut self,
        interface_id: &str,
        operation: [&str; N],
    ) -> Result<String, NetToolError> {
        let mut arguments = operation.into_iter().map(str::to_owned).collect::<Vec<_>>();
        arguments.push(interface_id.to_owned());
        let command = PlatformCommand {
            program: PathBuf::from("/usr/sbin/networksetup"),
            arguments,
        };
        let output = run_validated_platform_command(&mut self.runner, &command)?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                "networksetup state query failed",
                true,
            ))
        }
    }
}

pub(super) fn parse_macos_state(
    info: &str,
    v6_info: &str,
    dns_info: &str,
    mtu_info: &str,
) -> Result<NetworkDesiredState, NetToolError> {
    let ipv4 = if info.contains("DHCP Configuration") {
        Ipv4Configuration::Dhcp
    } else {
        let address = parse_ip_label(info, "IP address:")?;
        let mask = parse_ip_label(info, "Subnet mask:")?;
        let IpAddr::V4(address) = address else {
            return Err(platform_reader_error("macOS IPv4 address has wrong family"));
        };
        let IpAddr::V4(mask) = mask else {
            return Err(platform_reader_error(
                "macOS IPv4 subnet mask has wrong family",
            ));
        };
        let prefix_length = prefix_from_netmask(mask)?;
        if let Some(router) = parse_optional_ip_label(info, "Router:")? {
            if !router.is_unspecified() {
                return Err(platform_reader_error(
                    "macOS state contains a gateway not representable by this adapter",
                ));
            }
        }
        Ipv4Configuration::Static {
            addresses: vec![IpPrefix {
                address: IpAddr::V4(address),
                prefix_length,
            }],
        }
    };

    let ipv6 = if v6_info.contains("Off") || v6_info.contains("Disabled") {
        Ipv6Configuration::Disabled
    } else if v6_info.contains("Automatic") {
        Ipv6Configuration::Automatic
    } else {
        let address = parse_ip_label(v6_info, "IPv6 IP address:")?;
        let IpAddr::V6(address) = address else {
            return Err(platform_reader_error("macOS IPv6 address has wrong family"));
        };
        let prefix_length = parse_u8_label(v6_info, "Prefix Length:")?;
        if let Some(router) = parse_optional_ip_label(v6_info, "IPv6 Router:")? {
            if !router.is_unspecified() {
                return Err(platform_reader_error(
                    "macOS IPv6 state contains a gateway not representable by this adapter",
                ));
            }
        }
        Ipv6Configuration::Static {
            addresses: vec![IpPrefix {
                address: IpAddr::V6(address),
                prefix_length,
            }],
        }
    };

    let dns_servers = parse_macos_dns(dns_info)?;
    let mtu = parse_mtu(mtu_info)?;
    let state = NetworkDesiredState {
        ipv4,
        ipv6,
        dns: DnsConfiguration {
            automatic: dns_servers.is_empty(),
            servers: dns_servers,
            search_domains: Vec::new(),
        },
        routes: Vec::new(),
        mtu: Some(mtu),
    };
    state
        .validate()
        .map_err(|message| NetToolError::new(ErrorCode::ProtocolInvalid, message, false))?;
    Ok(state)
}

fn parse_ip_label(output: &str, label: &str) -> Result<IpAddr, NetToolError> {
    parse_optional_ip_label(output, label)?
        .ok_or_else(|| platform_reader_error(format!("macOS state is missing {label}")))
}

fn parse_optional_ip_label(output: &str, label: &str) -> Result<Option<IpAddr>, NetToolError> {
    let Some(value) = output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
    else {
        return Ok(None);
    };
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| platform_reader_error(format!("macOS state has invalid {label}")))
}

fn parse_u8_label(output: &str, label: &str) -> Result<u8, NetToolError> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(label).map(str::trim))
        .ok_or_else(|| platform_reader_error(format!("macOS state is missing {label}")))?
        .parse()
        .map_err(|_| platform_reader_error(format!("macOS state has invalid {label}")))
}

fn prefix_from_netmask(mask: Ipv4Addr) -> Result<u8, NetToolError> {
    let bits = u32::from(mask);
    let prefix = u8::try_from(bits.leading_ones())
        .map_err(|_| platform_reader_error("IPv4 prefix length overflow"))?;
    if bits
        != if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    {
        return Err(platform_reader_error("macOS subnet mask is not contiguous"));
    }
    Ok(prefix)
}

fn parse_macos_dns(output: &str) -> Result<Vec<IpAddr>, NetToolError> {
    if output.contains("There aren't any DNS Servers") || output.trim().is_empty() {
        return Ok(Vec::new());
    }
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse()
                .map_err(|_| platform_reader_error("macOS DNS output is not an IP address"))
        })
        .collect()
}

fn parse_mtu(output: &str) -> Result<u32, NetToolError> {
    output
        .split("Current Setting:")
        .nth(1)
        .and_then(|value| value.split_whitespace().next())
        .map(|value| value.trim_end_matches(')'))
        .ok_or_else(|| platform_reader_error("macOS MTU output is invalid"))?
        .parse()
        .map_err(|_| platform_reader_error("macOS MTU is invalid"))
}

/// 將 desired state 轉成 macOS `networksetup` command sequence。
///
/// 此 builder 不執行命令；routes 尚未有安全的 `networksetup` 對應操作，因此會明確拒絕。
///
/// # Errors
///
/// Interface ID 不安全、desired state 無效、routes 存在或 macOS 不支援的設定時回傳錯誤。
pub fn build_macos_networksetup_commands(
    interface_id: &str,
    desired: &NetworkDesiredState,
) -> Result<Vec<PlatformCommand>, NetToolError> {
    validate_interface(interface_id)?;
    desired
        .validate()
        .map_err(|message| invalid(message.to_owned()))?;
    if !desired.routes.is_empty() || !desired.dns.search_domains.is_empty() {
        return Err(NetToolError::new(
            ErrorCode::Unsupported,
            "macOS networksetup adapter does not apply routes or DNS search domains",
            false,
        ));
    }
    let program = PathBuf::from("/usr/sbin/networksetup");
    let mut commands = Vec::new();
    match &desired.ipv4 {
        Ipv4Configuration::Dhcp => commands.push(command(&program, ["-setdhcp", interface_id])),
        Ipv4Configuration::Disabled => commands.push(command(
            &program,
            ["-setmanual", interface_id, "0.0.0.0", "0.0.0.0", "0.0.0.0"],
        )),
        Ipv4Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid(
                    "macOS networksetup requires exactly one IPv4 address",
                ));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("macOS static IPv4 requires an address"));
            };
            let IpAddr::V4(address) = prefix.address else {
                return Err(invalid("macOS IPv4 adapter received a non-IPv4 address"));
            };
            let mask = ipv4_netmask(prefix.prefix_length)?;
            commands.push(command(
                &program,
                [
                    "-setmanual",
                    interface_id,
                    &address.to_string(),
                    &mask,
                    "0.0.0.0",
                ],
            ));
        }
    }
    match &desired.ipv6 {
        Ipv6Configuration::Automatic => {
            commands.push(command(&program, ["-setv6automatic", interface_id]));
        }
        Ipv6Configuration::Disabled => {
            commands.push(command(&program, ["-setv6off", interface_id]));
        }
        Ipv6Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid(
                    "macOS networksetup requires exactly one IPv6 address",
                ));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("macOS static IPv6 requires an address"));
            };
            let IpAddr::V6(address) = prefix.address else {
                return Err(invalid("macOS IPv6 adapter received a non-IPv6 address"));
            };
            commands.push(command(
                &program,
                [
                    "-setv6manual",
                    interface_id,
                    &address.to_string(),
                    &prefix.prefix_length.to_string(),
                    "::",
                ],
            ));
        }
    }
    if desired.dns.automatic {
        commands.push(command(&program, ["-setdnsservers", interface_id, "Empty"]));
    } else {
        let mut arguments = vec!["-setdnsservers".to_owned(), interface_id.to_owned()];
        arguments.extend(desired.dns.servers.iter().map(ToString::to_string));
        if desired.dns.servers.is_empty() {
            arguments.push("Empty".to_owned());
        }
        commands.push(PlatformCommand {
            program: program.clone(),
            arguments,
        });
    }
    if let Some(mtu) = desired.mtu {
        commands.push(command(
            &program,
            ["-setMTU", interface_id, &mtu.to_string()],
        ));
    }
    validate_commands(&commands)?;
    Ok(commands)
}
