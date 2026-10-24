//! Human-readable device labels for pairing and session IPC.
//!
//! Socket addresses and bind addresses (`0.0.0.0:0`, `192.168.4.25:55170`) are
//! transport coordinates, not names. The UI must never show them as the remote
//! device. A name comes from HELLO (`deviceName` / `deviceType`) or from this
//! daemon's own hostname / `--device-name`. When nothing usable is known, the
//! placeholder is [`PeerDisplay::UNKNOWN_NAME`].

/// Placeholder shown when HELLO carries no usable device name.
pub const UNKNOWN_DEVICE_NAME: &str = "Unknown device";

const UNKNOWN_DEVICE_TYPE: &str = "unknown";

/// Types this daemon will advertise or accept from a peer HELLO.
const KNOWN_DEVICE_TYPES: &[&str] = &["phone", "tablet", "laptop", "desktop", "browser"];

/// Maximum accepted device-name length, in Unicode scalars.
const MAX_DEVICE_NAME_CHARS: usize = 128;

/// Name and type safe to put in `pairing.request` and `session.connected`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDisplay {
    pub device_name: String,
    pub device_type: String,
}

impl PeerDisplay {
    pub const UNKNOWN_NAME: &'static str = UNKNOWN_DEVICE_NAME;

    /// No usable identity yet.
    pub fn unknown() -> Self {
        Self {
            device_name: UNKNOWN_DEVICE_NAME.to_string(),
            device_type: UNKNOWN_DEVICE_TYPE.to_string(),
        }
    }

    /// Build a display label from optional HELLO fields.
    ///
    /// Bind addresses, raw IPs, and `ip:port` socket addresses are discarded.
    /// A missing or unusable name becomes [`UNKNOWN_DEVICE_NAME`]. An unrecognized
    /// type becomes `"unknown"` rather than a guessed platform.
    pub fn from_hello(name: Option<&str>, device_type: Option<&str>) -> Self {
        Self {
            device_name: usable_device_name(name)
                .unwrap_or_else(|| UNKNOWN_DEVICE_NAME.to_string()),
            device_type: normalize_remote_device_type(device_type),
        }
    }
}

/// Device name and type this daemon seals into its own HELLO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceClaim {
    pub device_name: String,
    pub device_type: String,
}

/// Local name this process will advertise. `name` is empty when neither the
/// override nor the hostname is usable; HELLO then omits `deviceName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDeviceLabel {
    pub name: String,
    pub device_type: String,
}

/// Resolve the name advertised in outbound HELLO.
///
/// `--device-name` wins when it is a real name. Otherwise the machine hostname
/// is used, with a single trailing `.local` removed (macOS `hostname` form).
/// A bind address or socket address is never advertised.
pub fn resolve_local_label(
    name_override: Option<&str>,
    type_override: Option<&str>,
) -> LocalDeviceLabel {
    resolve_local_label_with_hostname(name_override, type_override, system_hostname().as_deref())
}

/// Same as [`resolve_local_label`], with the hostname injected so tests do not
/// depend on the machine they run on.
pub fn resolve_local_label_with_hostname(
    name_override: Option<&str>,
    type_override: Option<&str>,
    hostname: Option<&str>,
) -> LocalDeviceLabel {
    let host = hostname.map(strip_trailing_local);
    let name = usable_device_name(name_override)
        .or_else(|| usable_device_name(host.as_deref()))
        .unwrap_or_default();
    LocalDeviceLabel {
        name,
        device_type: advertised_device_type(type_override),
    }
}

/// Claim to seal into HELLO, or `None` when `name` is blank or address-shaped.
pub fn claim_from_local(name: &str, device_type: &str) -> Option<DeviceClaim> {
    let device_name = usable_device_name(Some(name))?;
    Some(DeviceClaim {
        device_name,
        device_type: advertised_device_type(Some(device_type)),
    })
}

/// `session.connected` payload. The display name is re-checked so a socket
/// address cannot leak into the event even if a caller passes one through.
pub fn session_connected_payload(
    remote_peer_id: &str,
    negotiated_capabilities: &[String],
    display: &PeerDisplay,
) -> serde_json::Value {
    let shown = PeerDisplay::from_hello(Some(&display.device_name), Some(&display.device_type));
    serde_json::json!({
        "remote_peer_id": remote_peer_id,
        "negotiated_capabilities": negotiated_capabilities,
        "remote_device_name": shown.device_name,
        "remote_device_type": shown.device_type,
    })
}

/// A name a person can recognize. `None` for blanks, control characters,
/// over-long strings, IP addresses, and socket addresses.
pub fn usable_device_name(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_DEVICE_NAME_CHARS {
        return None;
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    if is_raw_address(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

fn normalize_remote_device_type(raw: Option<&str>) -> String {
    match canonical_device_type(raw) {
        Some(kind) => kind,
        None => UNKNOWN_DEVICE_TYPE.to_string(),
    }
}

/// Type this daemon puts in its own HELLO. An omitted or unrecognized override
/// stays `"desktop"` — the daemon is a desktop sidecar, not an unknown peer.
fn advertised_device_type(raw: Option<&str>) -> String {
    canonical_device_type(raw).unwrap_or_else(|| "desktop".to_string())
}

fn canonical_device_type(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if KNOWN_DEVICE_TYPES.contains(&lower.as_str()) {
        Some(lower)
    } else {
        None
    }
}

/// True for bind addresses, raw IPs, `ip:port`, and URLs whose host is an IP.
fn is_raw_address(name: &str) -> bool {
    if name.parse::<std::net::IpAddr>().is_ok() || name.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    if let Some(inner) = name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        if inner.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }
    }
    if let Some((_, rest)) = name.split_once("://") {
        let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if hostport.parse::<std::net::SocketAddr>().is_ok()
            || hostport.parse::<std::net::IpAddr>().is_ok()
        {
            return true;
        }
    }
    false
}

fn system_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    let raw = std::str::from_utf8(&buf[..end]).ok()?.trim();
    if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

/// macOS `hostname` is often `Name.local`. One trailing suffix is presentation,
/// not part of the name a person recognizes.
fn strip_trailing_local(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_suffix(".local")
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_names_are_usable() {
        assert_eq!(
            usable_device_name(Some("  Evan's MacBook Pro  ")).as_deref(),
            Some("Evan's MacBook Pro")
        );
        assert_eq!(
            usable_device_name(Some("Mac Studio")).as_deref(),
            Some("Mac Studio")
        );
    }

    #[test]
    fn bind_and_socket_addresses_are_not_names() {
        for raw in [
            "",
            "   ",
            "0.0.0.0",
            "0.0.0.0:0",
            "127.0.0.1:1",
            "192.168.4.25:55170",
            "::",
            "[::]",
            "[::1]:55170",
            "ws://192.168.4.25:9100",
            "ws://0.0.0.0:9100",
        ] {
            assert!(
                usable_device_name(Some(raw)).is_none(),
                "{raw:?} must not be a device name"
            );
        }
    }

    #[test]
    fn hello_display_uses_name_or_placeholder() {
        let named = PeerDisplay::from_hello(Some("Evan's MacBook Pro"), Some("Laptop"));
        assert_eq!(named.device_name, "Evan's MacBook Pro");
        assert_eq!(named.device_type, "laptop");

        let missing = PeerDisplay::from_hello(None, None);
        assert_eq!(missing, PeerDisplay::unknown());

        let socket = PeerDisplay::from_hello(Some("192.168.4.25:55170"), Some("nope"));
        assert_eq!(socket.device_name, UNKNOWN_DEVICE_NAME);
        assert_eq!(socket.device_type, "unknown");

        let bind = PeerDisplay::from_hello(Some("0.0.0.0:0"), Some("desktop"));
        assert_eq!(bind.device_name, UNKNOWN_DEVICE_NAME);
        assert_eq!(bind.device_type, "desktop");
    }

    #[test]
    fn local_label_prefers_override_then_hostname() {
        let named = resolve_local_label_with_hostname(
            Some("Evan's MacBook Pro"),
            Some("laptop"),
            Some("ignored-host"),
        );
        assert_eq!(named.name, "Evan's MacBook Pro");
        assert_eq!(named.device_type, "laptop");

        let from_host =
            resolve_local_label_with_hostname(None, None, Some("Evans-MacBook-Pro.local"));
        assert_eq!(from_host.name, "Evans-MacBook-Pro");
        assert_eq!(from_host.device_type, "desktop");

        let bind_override_falls_through = resolve_local_label_with_hostname(
            Some("0.0.0.0:0"),
            Some("desktop"),
            Some("Mac Studio.local"),
        );
        assert_eq!(bind_override_falls_through.name, "Mac Studio");

        let nothing =
            resolve_local_label_with_hostname(Some("192.168.4.25:55170"), None, Some("0.0.0.0"));
        assert!(nothing.name.is_empty());
        assert!(claim_from_local(&nothing.name, &nothing.device_type).is_none());
    }

    #[test]
    fn claim_rejects_socket_and_keeps_a_real_name() {
        assert!(claim_from_local("0.0.0.0:0", "desktop").is_none());
        let claim = claim_from_local("Mac Studio", "desktop").expect("real name");
        assert_eq!(claim.device_name, "Mac Studio");
        assert_eq!(claim.device_type, "desktop");
    }

    #[test]
    fn session_connected_payload_never_carries_a_socket() {
        let payload = session_connected_payload(
            "identity-b64",
            &["bolt.file-hash".to_string()],
            &PeerDisplay {
                device_name: "192.168.4.25:55170".to_string(),
                device_type: "unknown".to_string(),
            },
        );
        assert_eq!(payload["remote_device_name"], UNKNOWN_DEVICE_NAME);
        assert_eq!(payload["remote_peer_id"], "identity-b64");
        assert_ne!(payload["remote_device_name"], "192.168.4.25:55170");

        let named = session_connected_payload(
            "identity-b64",
            &[],
            &PeerDisplay::from_hello(Some("Evan's MacBook Pro"), Some("laptop")),
        );
        assert_eq!(named["remote_device_name"], "Evan's MacBook Pro");
        assert_eq!(named["remote_device_type"], "laptop");
    }
}
