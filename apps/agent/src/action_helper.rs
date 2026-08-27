#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpSetPayload {
    interface_id: String,
    address: String,
    prefix_length: u8,
    gateway: Option<String>,
    #[serde(default)]
    confirm_timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpDhcpPayload {
    interface_id: String,
    #[serde(default)]
    confirm_timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsSetPayload {
    interface_id: String,
    servers: Vec<String>,
    #[serde(default)]
    confirm_timeout_seconds: Option<u64>,
}

#[allow(clippy::too_many_lines)]
pub(super) async fn execute(
    action: &str,
    payload: &[u8],
    operation_id: &str,
    dry_run: bool,
) -> Result<serde_json::Value, NetToolError> {
    let (operation, helper_operation_id) = match action {
        "ip.set" => {
            let request: IpSetPayload = serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid ip set payload: {error}"),
                    false,
                )
            })?;
            let address = request.address.parse::<std::net::IpAddr>().map_err(|_| {
                NetToolError::new(ErrorCode::InvalidArgument, "IP address is invalid", false)
            })?;
            let gateway = request
                .gateway
                .as_deref()
                .map(str::parse::<std::net::IpAddr>)
                .transpose()
                .map_err(|_| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "gateway address is invalid",
                        false,
                    )
                })?;
            if gateway.is_some_and(|value| value.is_ipv4() != address.is_ipv4()) {
                return Err(NetToolError::new(
                    ErrorCode::InvalidArgument,
                    "gateway address family does not match IP address",
                    false,
                ));
            }
            let (ipv4, ipv6, destination) = if address.is_ipv4() {
                (
                    nettool_domain::Ipv4Configuration::Static {
                        addresses: vec![nettool_domain::IpPrefix {
                            address,
                            prefix_length: request.prefix_length,
                        }],
                    },
                    nettool_domain::Ipv6Configuration::Automatic,
                    nettool_domain::IpPrefix {
                        address: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        prefix_length: 0,
                    },
                )
            } else {
                (
                    nettool_domain::Ipv4Configuration::Dhcp,
                    nettool_domain::Ipv6Configuration::Static {
                        addresses: vec![nettool_domain::IpPrefix {
                            address,
                            prefix_length: request.prefix_length,
                        }],
                    },
                    nettool_domain::IpPrefix {
                        address: std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                        prefix_length: 0,
                    },
                )
            };
            (
                PrivilegedOperation::NetworkApply {
                    interface_id: request.interface_id,
                    desired_state: NetworkDesiredState {
                        ipv4,
                        ipv6,
                        dns: nettool_domain::DnsConfiguration {
                            automatic: true,
                            servers: Vec::new(),
                            search_domains: Vec::new(),
                        },
                        routes: request
                            .gateway
                            .map(|_| nettool_domain::RouteConfiguration {
                                destination,
                                gateway,
                                metric: None,
                            })
                            .into_iter()
                            .collect(),
                        mtu: None,
                    },
                    confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                },
                operation_id.to_owned(),
            )
        }
        "ip.dhcp" => {
            let request: IpDhcpPayload = serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid ip dhcp payload: {error}"),
                    false,
                )
            })?;
            (
                PrivilegedOperation::NetworkApply {
                    interface_id: request.interface_id,
                    desired_state: NetworkDesiredState {
                        ipv4: nettool_domain::Ipv4Configuration::Dhcp,
                        ipv6: nettool_domain::Ipv6Configuration::Automatic,
                        dns: nettool_domain::DnsConfiguration {
                            automatic: true,
                            servers: Vec::new(),
                            search_domains: Vec::new(),
                        },
                        routes: Vec::new(),
                        mtu: None,
                    },
                    confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                },
                operation_id.to_owned(),
            )
        }
        "dns.set" => {
            let request: DnsSetPayload = serde_json::from_slice(payload).map_err(|error| {
                NetToolError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid dns set payload: {error}"),
                    false,
                )
            })?;
            let servers = request
                .servers
                .iter()
                .map(|value| value.parse::<std::net::IpAddr>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    NetToolError::new(
                        ErrorCode::InvalidArgument,
                        "DNS server address is invalid",
                        false,
                    )
                })?;
            (
                PrivilegedOperation::NetworkApply {
                    interface_id: request.interface_id,
                    desired_state: NetworkDesiredState {
                        ipv4: nettool_domain::Ipv4Configuration::Dhcp,
                        ipv6: nettool_domain::Ipv6Configuration::Automatic,
                        dns: nettool_domain::DnsConfiguration {
                            automatic: false,
                            servers,
                            search_domains: Vec::new(),
                        },
                        routes: Vec::new(),
                        mtu: None,
                    },
                    confirm_timeout_seconds: request.confirm_timeout_seconds.unwrap_or(60),
                },
                operation_id.to_owned(),
            )
        }
        _ => {
            return Err(NetToolError::new(
                ErrorCode::ActionUnsupported,
                "network helper action is not attached",
                false,
            ));
        }
    };
    helper_call(&helper_operation_id, operation, dry_run).await
}

#[allow(clippy::too_many_lines)]
pub(super) async fn helper_call(
    operation_id: &str,
    operation: PrivilegedOperation,
    dry_run: bool,
) -> Result<serde_json::Value, NetToolError> {
    if operation_id.trim().is_empty() {
        return Err(NetToolError::new(
            ErrorCode::InvalidArgument,
            "helper operation ID must not be empty",
            false,
        ));
    }
    operation
        .validate()
        .map_err(|message| NetToolError::new(ErrorCode::InvalidArgument, message, false))?;
    let path = configured_helper_socket()?;
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), connect_helper(path))
            .await
            .map_err(|_| {
                NetToolError::new(
                    ErrorCode::HelperTransportFailed,
                    "helper connect timed out",
                    true,
                )
            })?
            .map_err(|error| {
                NetToolError::new(
                    ErrorCode::HelperTransportFailed,
                    format!("helper connect failed: {error}"),
                    true,
                )
            })?;
    let request_id = format!("agent-{}", hex_node_id(random_session_id()?));
    let request = PrivilegedWireRequest {
        request_id: request_id.clone(),
        operation_id: operation_id.to_owned(),
        operation,
        dry_run,
    };
    let bytes = serde_json::to_vec(&request).map_err(|error| {
        NetToolError::new(
            ErrorCode::ProtocolInvalid,
            format!("helper request cannot be encoded: {error}"),
            false,
        )
    })?;
    if bytes.len() > 1_048_576 {
        return Err(NetToolError::new(
            ErrorCode::ControlFrameTooLarge,
            "helper request exceeds frame limit",
            false,
        ));
    }
    stream
        .write_u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX))
        .await
        .map_err(|error| {
            NetToolError::new(
                ErrorCode::HelperTransportFailed,
                format!("helper request length failed: {error}"),
                true,
            )
        })?;
    stream.write_all(&bytes).await.map_err(|error| {
        NetToolError::new(
            ErrorCode::HelperTransportFailed,
            format!("helper request failed: {error}"),
            true,
        )
    })?;
    stream.flush().await.map_err(|error| {
        NetToolError::new(
            ErrorCode::HelperTransportFailed,
            format!("helper request flush failed: {error}"),
            true,
        )
    })?;
    let length = tokio::time::timeout(Duration::from_secs(2), stream.read_u32())
        .await
        .map_err(|_| {
            NetToolError::new(
                ErrorCode::HelperTransportFailed,
                "helper response timed out",
                true,
            )
        })?
        .map_err(|error| {
            NetToolError::new(
                ErrorCode::HelperTransportFailed,
                format!("helper response length failed: {error}"),
                true,
            )
        })? as usize;
    if length == 0 || length > 1_048_576 {
        return Err(NetToolError::new(
            ErrorCode::ControlFrameTooLarge,
            "helper response length is invalid",
            false,
        ));
    }
    let mut response_bytes = vec![0_u8; length];
    stream
        .read_exact(&mut response_bytes)
        .await
        .map_err(|error| {
            NetToolError::new(
                ErrorCode::HelperTransportFailed,
                format!("helper response failed: {error}"),
                true,
            )
        })?;
    let response: PrivilegedResponse =
        serde_json::from_slice(&response_bytes).map_err(|error| {
            NetToolError::new(
                ErrorCode::ProtocolInvalid,
                format!("helper response is invalid: {error}"),
                false,
            )
        })?;
    if response.request_id != request_id {
        return Err(NetToolError::new(
            ErrorCode::ProtocolInvalid,
            "helper response request ID mismatch",
            false,
        ));
    }
    if let Some(error) = response.error {
        return Err(NetToolError::new(
            ErrorCode::HelperExecutionFailed,
            error.message,
            error.retryable,
        ));
    }
    response.result.ok_or_else(|| {
        NetToolError::new(
            ErrorCode::HelperExecutionFailed,
            "helper response has no result",
            false,
        )
    })
}

fn configured_helper_socket() -> Result<PathBuf, NetToolError> {
    configured_helper_socket_from(std::env::var_os("NETTOOL_HELPER_SOCKET"))
}

fn configured_helper_socket_from(
    path: Option<std::ffi::OsString>,
) -> Result<PathBuf, NetToolError> {
    path.map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            NetToolError::new(
                ErrorCode::HelperNotConfigured,
                "privileged helper socket is not configured",
                false,
            )
        })
}

#[cfg(unix)]
async fn connect_helper(path: PathBuf) -> Result<UnixStream, std::io::Error> {
    UnixStream::connect(path).await
}

#[cfg(windows)]
#[allow(clippy::unused_async)]
async fn connect_helper(path: PathBuf) -> Result<NamedPipeClient, std::io::Error> {
    ClientOptions::new().open(path)
}

#[cfg(test)]
mod tests {
    use super::configured_helper_socket_from;
    use nettool_error::ErrorCode;

    #[test]
    fn missing_helper_socket_fails_closed_with_explicit_code() {
        let error = configured_helper_socket_from(None).expect_err("socket must be configured");
        assert_eq!(error.code, ErrorCode::HelperNotConfigured);
        assert_eq!(error.message, "privileged helper socket is not configured");
        assert!(!error.retryable);
    }

    #[test]
    fn empty_helper_socket_fails_closed_with_explicit_code() {
        let error = configured_helper_socket_from(Some(std::ffi::OsString::new()))
            .expect_err("empty socket must be rejected");
        assert_eq!(error.code, ErrorCode::HelperNotConfigured);
    }
}
