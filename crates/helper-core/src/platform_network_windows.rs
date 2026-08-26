#[allow(clippy::wildcard_imports)]
use super::*;

impl<R> WindowsNetshStateReader<R> {
    /// 建立 reader；命令由注入的 runner 執行。
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: CommandRunner> PlatformStateReader for WindowsNetshStateReader<R> {
    fn read_state(&mut self, interface_id: &str) -> Result<NetworkDesiredState, NetToolError> {
        validate_interface(interface_id)?;
        let output = self.query(interface_id)?;
        parse_windows_json_state(&output, interface_id)
    }
}

impl<R: CommandRunner> WindowsNetshStateReader<R> {
    fn query(&mut self, interface_id: &str) -> Result<String, NetToolError> {
        let arguments = vec![
            "-NoLogo".to_owned(),
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-ExecutionPolicy".to_owned(),
            "Bypass".to_owned(),
            "-Command".to_owned(),
            WINDOWS_STATE_QUERY.to_owned(),
            "--".to_owned(),
            interface_id.to_owned(),
        ];
        let command = PlatformCommand {
            program: PathBuf::from(POWERSHELL_EXE),
            arguments,
        };
        let output = run_validated_platform_command(&mut self.runner, &command)?;
        if output.success {
            Ok(output.stdout)
        } else {
            Err(NetToolError::new(
                ErrorCode::HelperExecutionFailed,
                "PowerShell state query failed",
                true,
            ))
        }
    }
}

pub(super) fn validate_state_query_command(command: &PlatformCommand) -> Result<(), NetToolError> {
    const PREFIX: [&str; 6] = [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
    ];
    if command.arguments.len() != PREFIX.len() + 3
        || command.arguments[..PREFIX.len()]
            .iter()
            .map(String::as_str)
            .ne(PREFIX)
        || command.arguments[PREFIX.len()] != WINDOWS_STATE_QUERY
        || command.arguments[PREFIX.len() + 1] != "--"
    {
        return Err(invalid(
            "PowerShell state query arguments are not allowlisted",
        ));
    }
    validate_interface(&command.arguments[PREFIX.len() + 2])
}

const POWERSHELL_EXE: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const WINDOWS_STATE_SCHEMA_VERSION: u32 = 1;

// 介面名稱只作為獨立 argv 傳給固定 script，避免 PowerShell injection；reader 不回退到
// 語系相關的 netsh 文字輸出，因為不完整 snapshot 會破壞 Safe Apply 的 rollback 保證。
const WINDOWS_STATE_QUERY: &str = r"& {
param([Parameter(Mandatory=$true)][string]$InterfaceId)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$adapter = @(Get-NetAdapter -Name $InterfaceId -ErrorAction Stop)
if ($adapter.Count -ne 1) { throw 'interface lookup did not return exactly one adapter' }
$index = $adapter[0].ifIndex
$v4Interface = @(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
$v6Interface = @(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction Stop)
if ($v4Interface.Count -ne 1 -or $v6Interface.Count -ne 1) { throw 'IP interface lookup did not return exactly one entry per family' }
$v4 = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.AddressState -eq 'Preferred' }) |
    ForEach-Object { @{ address=$_.IPAddress; prefix_length=[int]$_.PrefixLength } }
$v6 = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction Stop |
    Where-Object { $_.AddressState -eq 'Preferred' -and $_.PrefixOrigin -eq 'Manual' }) |
    ForEach-Object { @{ address=$_.IPAddress; prefix_length=[int]$_.PrefixLength } }
$routes = @(Get-NetRoute -InterfaceIndex $index -ErrorAction Stop |
    Where-Object { $_.RouteMetric -ge 0 -and $_.NextHop -notin @('0.0.0.0','::') })
$gateways = @($routes | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
    ForEach-Object { $_.NextHop })
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $index -ErrorAction Stop |
    ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
$ipv6State = if ($v6.Count -gt 0) {
    'static'
} elseif ($v6Interface[0].RouterDiscovery -eq 'Disabled' -and $v6Interface[0].Dhcp -eq 'Disabled') {
    'disabled'
} else {
    'automatic'
}
@{ schema_version=1; interface_count=$adapter.Count; interface_id=$adapter[0].Name;
   ipv4=@{ dhcp=($v4Interface[0].Dhcp -eq 'Enabled'); addresses=@($v4) };
   ipv6=@{ state=$ipv6State; addresses=@($v6) };
   dns=@{ servers=@($dns) }; mtu=[int]$v4Interface[0].NlMtu;
   default_gateways=@($gateways); route_count=$routes.Count } | ConvertTo-Json -Compress -Depth 6
}";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsStateDocument {
    schema_version: u32,
    interface_count: u32,
    interface_id: String,
    ipv4: WindowsIpv4State,
    ipv6: WindowsIpv6State,
    dns: WindowsDnsState,
    mtu: u32,
    default_gateways: Vec<String>,
    route_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsIpv4State {
    dhcp: bool,
    addresses: Vec<WindowsAddress>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsIpv6State {
    state: String,
    addresses: Vec<WindowsAddress>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsDnsState {
    servers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsAddress {
    address: String,
    prefix_length: u8,
}

pub(super) fn parse_windows_json_state(
    output: &str,
    expected_interface_id: &str,
) -> Result<NetworkDesiredState, NetToolError> {
    let document: WindowsStateDocument = serde_json::from_str(output)
        .map_err(|_| platform_reader_error("Windows state JSON is malformed"))?;
    if document.schema_version != WINDOWS_STATE_SCHEMA_VERSION
        || document.interface_count != 1
        || document.interface_id != expected_interface_id
        || document.route_count != 0
        || !document.default_gateways.is_empty()
        || document.dns.servers.len() > 16
        || !(576..=65_535).contains(&document.mtu)
    {
        return Err(platform_reader_error(
            "Windows state JSON failed schema validation",
        ));
    }
    let ipv4 = if document.ipv4.dhcp {
        Ipv4Configuration::Dhcp
    } else {
        let address = one_ipv4_address(&document.ipv4.addresses)?;
        Ipv4Configuration::Static {
            addresses: vec![IpPrefix {
                address: IpAddr::V4(address.0),
                prefix_length: address.1,
            }],
        }
    };

    let ipv6 = match document.ipv6.state.as_str() {
        "disabled" => {
            if !document.ipv6.addresses.is_empty() {
                return Err(platform_reader_error("disabled IPv6 has addresses"));
            }
            Ipv6Configuration::Disabled
        }
        "automatic" => Ipv6Configuration::Automatic,
        "static" => {
            let address = one_ipv6_address(&document.ipv6.addresses)?;
            Ipv6Configuration::Static {
                addresses: vec![IpPrefix {
                    address: IpAddr::V6(address.0),
                    prefix_length: address.1,
                }],
            }
        }
        _ => return Err(platform_reader_error("Windows IPv6 state is invalid")),
    };

    let servers = document
        .dns
        .servers
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| platform_reader_error("Windows DNS address is invalid"))
        })
        .collect::<Result<Vec<IpAddr>, _>>()?;
    let state = NetworkDesiredState {
        ipv4,
        ipv6,
        dns: DnsConfiguration {
            automatic: servers.is_empty(),
            servers,
            search_domains: Vec::new(),
        },
        routes: Vec::new(),
        mtu: Some(document.mtu),
    };
    state
        .validate()
        .map_err(|message| NetToolError::new(ErrorCode::ProtocolInvalid, message, false))?;
    Ok(state)
}

fn one_ipv4_address(addresses: &[WindowsAddress]) -> Result<(Ipv4Addr, u8), NetToolError> {
    if addresses.len() != 1 {
        return Err(platform_reader_error(
            "Windows static IPv4 must have one address",
        ));
    }
    let address = &addresses[0];
    Ok((
        address
            .address
            .parse()
            .map_err(|_| platform_reader_error("Windows IPv4 address is invalid"))?,
        address.prefix_length,
    ))
}

fn one_ipv6_address(addresses: &[WindowsAddress]) -> Result<(Ipv6Addr, u8), NetToolError> {
    if addresses.len() != 1 {
        return Err(platform_reader_error(
            "Windows static IPv6 must have one address",
        ));
    }
    let address = &addresses[0];
    Ok((
        address
            .address
            .split('%')
            .next()
            .ok_or_else(|| platform_reader_error("Windows IPv6 address is invalid"))?
            .parse()
            .map_err(|_| platform_reader_error("Windows IPv6 address is invalid"))?,
        address.prefix_length,
    ))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[derive(Default)]
    struct FixtureRunner {
        output: String,
        success: Option<bool>,
        program: Option<PathBuf>,
        arguments: Vec<String>,
    }

    impl CommandRunner for FixtureRunner {
        fn run(
            &mut self,
            program: &Path,
            arguments: &[String],
        ) -> Result<CommandOutput, NetToolError> {
            self.program = Some(program.to_owned());
            self.arguments = arguments.to_owned();
            Ok(CommandOutput {
                success: self.success.unwrap_or(true),
                stdout: self.output.clone(),
                stderr: String::new(),
            })
        }
    }

    fn fixture(interface_id: &str) -> String {
        format!(
            r#"{{"schema_version":1,"interface_count":1,"interface_id":"{interface_id}","ipv4":{{"dhcp":true,"addresses":[]}},"ipv6":{{"state":"disabled","addresses":[]}},"dns":{{"servers":[]}},"mtu":1500,"default_gateways":[],"route_count":0}}"#
        )
    }

    #[test]
    fn reader_uses_fixed_powershell_and_independent_alias_argument() {
        let interface_id = "Office ' | Get-Process *";
        let runner = FixtureRunner {
            output: fixture(interface_id),
            ..FixtureRunner::default()
        };
        let mut reader = WindowsNetshStateReader::new(runner);
        assert!(reader.read_state(interface_id).is_ok());
        assert_eq!(
            reader.runner.program.as_deref(),
            Some(Path::new(POWERSHELL_EXE))
        );
        assert_eq!(
            reader.runner.arguments.last(),
            Some(&interface_id.to_owned())
        );
        assert!(reader.runner.arguments[6].contains("Get-NetAdapter"));
        assert!(reader.runner.arguments[6].contains("NlMtu"));
        assert!(reader.runner.arguments[6].contains("PrefixOrigin -eq 'Manual'"));
        assert!(reader.runner.arguments[6].contains("OutputEncoding"));
        assert!(!reader.runner.arguments[6].contains(interface_id));
    }

    #[test]
    fn reader_returns_execution_failure_without_parsing_stdout() {
        let runner = FixtureRunner {
            output: fixture("Ethernet"),
            success: Some(false),
            ..FixtureRunner::default()
        };
        let mut reader = WindowsNetshStateReader::new(runner);
        let error = reader
            .read_state("Ethernet")
            .expect_err("failed PowerShell query must not parse stdout");
        assert_eq!(error.code, ErrorCode::HelperExecutionFailed);
    }

    #[test]
    fn state_query_validation_rejects_script_tampering_extra_arguments_and_unsafe_alias() {
        let query = |interface_id: &str| PlatformCommand {
            program: PathBuf::from(POWERSHELL_EXE),
            arguments: vec![
                "-NoLogo".to_owned(),
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-ExecutionPolicy".to_owned(),
                "Bypass".to_owned(),
                "-Command".to_owned(),
                WINDOWS_STATE_QUERY.to_owned(),
                "--".to_owned(),
                interface_id.to_owned(),
            ],
        };

        assert!(validate_state_query_command(&query("Ethernet")).is_ok());

        let mut tampered = query("Ethernet");
        tampered.arguments[6].push_str("; Get-Process");
        assert!(validate_state_query_command(&tampered).is_err());

        let mut extra = query("Ethernet");
        extra.arguments.push("unexpected".to_owned());
        assert!(validate_state_query_command(&extra).is_err());

        let unsafe_alias = query("Office\r\nGet-Process");
        assert!(validate_state_query_command(&unsafe_alias).is_err());
    }

    #[test]
    fn parser_accepts_representative_static_dhcp_ipv6_dns_and_mtu_state() {
        let json = r#"{"schema_version":1,"interface_count":1,"interface_id":"Ethernet 2","ipv4":{"dhcp":false,"addresses":[{"address":"192.0.2.10","prefix_length":24}]},"ipv6":{"state":"static","addresses":[{"address":"2001:db8::10%12","prefix_length":64}]},"dns":{"servers":["192.0.2.53","2001:db8::53"]},"mtu":9000,"default_gateways":[],"route_count":0}"#;
        let state = parse_windows_json_state(json, "Ethernet 2").expect("valid fixture");
        assert!(matches!(state.ipv4, Ipv4Configuration::Static { .. }));
        assert!(matches!(state.ipv6, Ipv6Configuration::Static { .. }));
        assert_eq!(state.dns.servers.len(), 2);
        assert_eq!(state.mtu, Some(9000));
    }

    #[test]
    fn parser_fails_closed_for_missing_fields_malformed_json_duplicates_routes_and_dns_overflow() {
        let missing = fixture("Ethernet").replace("\"mtu\":1500,", "");
        assert!(parse_windows_json_state(&missing, "Ethernet").is_err());
        assert!(parse_windows_json_state("not json", "Ethernet").is_err());
        let duplicate =
            fixture("Ethernet").replace("\"interface_count\":1", "\"interface_count\":2");
        assert!(parse_windows_json_state(&duplicate, "Ethernet").is_err());
        let route = fixture("Ethernet").replace("\"route_count\":0", "\"route_count\":1");
        assert!(parse_windows_json_state(&route, "Ethernet").is_err());
        let dns = (0..17)
            .map(|index| format!("\"192.0.2.{}\"", index + 1))
            .collect::<Vec<_>>()
            .join(",");
        let too_many_dns =
            fixture("Ethernet").replace("\"servers\":[]", &format!("\"servers\":[{dns}]"));
        assert!(parse_windows_json_state(&too_many_dns, "Ethernet").is_err());
    }

    #[test]
    fn parser_rejects_interface_mismatch_and_invalid_address_state() {
        let valid = fixture("Ethernet");
        assert!(parse_windows_json_state(&valid, "Wi-Fi").is_err());

        let invalid_dns = valid.replace("\"servers\":[]", "\"servers\":[\"not-an-ip\"]");
        assert!(parse_windows_json_state(&invalid_dns, "Ethernet").is_err());

        let invalid_ipv6_state = valid.replace("\"state\":\"disabled\"", "\"state\":\"unknown\"");
        assert!(parse_windows_json_state(&invalid_ipv6_state, "Ethernet").is_err());

        let invalid_mtu = valid.replace("\"mtu\":1500", "\"mtu\":128");
        assert!(parse_windows_json_state(&invalid_mtu, "Ethernet").is_err());
    }
}

/// 將 desired state 轉成 Windows `netsh.exe` command sequence。
///
/// 使用固定 System32 executable 與獨立 argv；不經 PowerShell 或 shell。Routes 與 DNS
/// search domains 尚未具備完整 read-back/rollback 證據時會拒絕。
///
/// # Errors
///
/// 欄位驗證失敗、routes/search domains 存在或平台尚未支援的設定時回傳錯誤。
#[allow(clippy::too_many_lines)]
pub fn build_windows_netsh_commands(
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
            "Windows netsh adapter does not apply routes or DNS search domains",
            false,
        ));
    }
    let program = PathBuf::from(r"C:\Windows\System32\netsh.exe");
    let mut commands = Vec::new();
    match &desired.ipv4 {
        Ipv4Configuration::Dhcp => commands.push(command(
            &program,
            [
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={interface_id}"),
                "source=dhcp",
            ],
        )),
        Ipv4Configuration::Disabled => commands.push(command(
            &program,
            [
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={interface_id}"),
                "source=static",
                "addr=0.0.0.0",
                "mask=0.0.0.0",
                "gateway=none",
            ],
        )),
        Ipv4Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid("Windows netsh requires exactly one IPv4 address"));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("Windows static IPv4 requires an address"));
            };
            let IpAddr::V4(address) = prefix.address else {
                return Err(invalid("Windows IPv4 adapter received a non-IPv4 address"));
            };
            let mask = ipv4_netmask(prefix.prefix_length)?;
            commands.push(command(
                &program,
                [
                    "interface",
                    "ipv4",
                    "set",
                    "address",
                    &format!("name={interface_id}"),
                    "source=static",
                    &format!("addr={address}"),
                    &format!("mask={mask}"),
                    "gateway=none",
                ],
            ));
        }
    }
    match &desired.ipv6 {
        Ipv6Configuration::Automatic => commands.push(command(
            &program,
            [
                "interface",
                "ipv6",
                "set",
                "address",
                &format!("interface={interface_id}"),
                "source=dhcp",
            ],
        )),
        Ipv6Configuration::Disabled => commands.push(command(
            &program,
            [
                "interface",
                "ipv6",
                "set",
                "address",
                &format!("interface={interface_id}"),
                "source=none",
            ],
        )),
        Ipv6Configuration::Static { addresses } => {
            if addresses.len() != 1 {
                return Err(invalid("Windows netsh requires exactly one IPv6 address"));
            }
            let Some(prefix) = addresses.first() else {
                return Err(invalid("Windows static IPv6 requires an address"));
            };
            let IpAddr::V6(address) = prefix.address else {
                return Err(invalid("Windows IPv6 adapter received a non-IPv6 address"));
            };
            commands.push(command(
                &program,
                [
                    "interface",
                    "ipv6",
                    "set",
                    "address",
                    &format!("interface={interface_id}"),
                    &format!("address={address}"),
                    &format!("prefixlength={}", prefix.prefix_length),
                    "store=active",
                ],
            ));
        }
    }
    let mut dns_arguments = vec![
        "interface".to_owned(),
        "ipv4".to_owned(),
        "set".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface_id}"),
        "source=static".to_owned(),
    ];
    if desired.dns.automatic {
        "source=dhcp".clone_into(&mut dns_arguments[5]);
    } else if let Some(server) = desired.dns.servers.first() {
        dns_arguments.push(format!("address={server}"));
        dns_arguments.push("validate=no".to_owned());
    } else {
        return Err(invalid("Windows static DNS requires at least one server"));
    }
    commands.push(PlatformCommand {
        program: program.clone(),
        arguments: dns_arguments,
    });
    if let Some(mtu) = desired.mtu {
        commands.push(command(
            &program,
            [
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &format!("interface={interface_id}"),
                &format!("mtu={mtu}"),
                "store=active",
            ],
        ));
    }
    validate_commands(&commands)?;
    Ok(commands)
}
