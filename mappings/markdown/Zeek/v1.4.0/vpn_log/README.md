# Event Dossier: Zeek vpn.log

### Summary:
- **Description**: Translates a Zeek vpn.log to OCSF Tunnel Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.4.0/classes/tunnel_activity](https://schema.ocsf.io/1.4.0/classes/tunnel_activity)  
  - [https://docs.zeek.org/en/master/logs/vpn.html](https://docs.zeek.org/en/master/logs/vpn.html)
  - [https://github.com/corelight/zeek-community-id](https://github.com/corelight/zeek-community-id)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| `metadata.version` | "1.4.0" | String |
| `category_uid` | 4 | Integer |
| `class_uid` | 4014 | Integer |
| `metadata.product.name` | "Zeek" | String |
| `metadata.product.vendor_name` | "Zeek" | String |
| `severity_id` | 1 | Integer |
| `activity_id` | 1 | Integer |
| `activity_name` | "Open" | String |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| `time` | `ts` | Timestamp when the VPN connection was detected. | Convert to epoch value. Type: `timestamp_t` (Long) |
| `start_time` | `ts` | Timestamp when the VPN connection was detected. | Convert to epoch value. Type: `timestamp_t` (Long) |
| `metadata.logged_time` | `_write_ts` | Timestamp when the log entry was written to disk. | Convert to epoch value. Type: `timestamp_t` (Long) |
| `metadata.loggers[].name` | `_system_name` | Name of the logging subsystem. | Type: `string_t` |
| `metadata.log_name` | `_path` | Log name. | Type: `string_t` |
| `metadata.uid` | `uid` | Unique ID for the connection. | Type: `string_t` |
| `src_endpoint.ip` | `id.orig_h` | Client's IP address. | Type: `ip_t` |
| `src_endpoint.port` | `id.orig_p` | Client's port number. | Type: `port_t` (Integer) |
| `dst_endpoint.ip` | `id.resp_h` | Server's IP address. | Type: `ip_t` |
| `dst_endpoint.port` | `id.resp_p` | Server's port number. | Type: `port_t` (Integer) |
| `connection_info.protocol_name` | `proto` | Transport protocol. | Values: "tcp"/"udp". Type: `string_t` |
| `tunnel.type` | `vpn_type` | VPN protocol type. | Strip "VPNInsights::" prefix. Type: `string_t` |
| `duration` | `duration` | Connection duration. | Convert to milliseconds. Type: `integer_t` |
| `traffic.bytes_in` | `resp_bytes` | Server-to-client bytes. | Type: `integer_t` |
| `traffic.bytes_out` | `orig_bytes` | Client-to-server bytes. | Type: `integer_t` |
| `tls.server_name` | `server_name` | TLS server hostname. | Only for TLS-based VPNs. Type: `string_t` |
| `tls.subject` | `subject` | Certificate subject in TLS connection. | Only for TLS-based VPNs. Validate PEM formatting. Type: `string_t` |
| `tls.issuer` | `issuer` | Certificate issuer in TLS connection. | Only for TLS-based VPNs. Type: `string_t` |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| `type_uid` | `activity_id` | Type identifier. | Calculate as `(4014 * 100) + activity_id = 401401`. |
| `status_id` | `duration` | Session status. | If `duration > 0` → `1` (Success), else `0` (Unknown). Type: `integer_t` |
| `traffic.bytes` | `orig_bytes`, `resp_bytes` | Total bytes transferred. | Sum both fields. Type: `integer_t` |
| `tls.ja3_hash.value` | `ja3` | Client TLS fingerprint. | Only for TLS-based VPNs. Type: `string_t` |
| `tls.ja3_hash.algorithm_id` | `ja3` | Hash algorithm for JA3. | If `ja3` exists, set to 1 (MD5). Type: `integer_t` |
| `tls.ja3s_hash.value` | ja3s | Server TLS fingerprint. | Only for TLS-based VPNs. Type: `string_t` |
| `tls.ja3s_hash.algorithm_id` | ja3s | Hash algorithm for JA3S. | If `ja3s` exists, set to 1 (MD5). Type: `integer_t` |
| `auth_info.auth_protocol` | `authentication_method` | Authentication method. | Map "certificate" → `5` (X509), "psk" → `14`. Type: `integer_t` |
| `tunnel.dst_endpoint.port` | `vpn_port` | Service port. | Use when different from `id.resp_p`. Type: `port_t` |

### Unmapped:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| `observables[].value` | `community_id` | Network flow hash. | Type: `string_t`. Could map to `network_traffic.community_id` if defined in custom extensions |
| `status_detail` | `stage` | Connection phase. | "handshake" → "In Progress", "established" → "Success". Requires OCSF extension. |
| `tls.cipher_suite` | `cipher_suite` | Encryption suite. | Pending OCSF TLS object expansion for non-web protocols |
| `evidence.observables[].value` | `ja3_string` | JA3 raw values. | No direct OCSF 1.4.0 field for raw JA3 strings |
| `auth_info.credential` | `authentication_method` | PSK/password values. | Sensitive data excluded per OCSF best practices |