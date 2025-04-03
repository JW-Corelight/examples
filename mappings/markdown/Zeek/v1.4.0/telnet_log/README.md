# Event Dossier: Zeek telnet.log

### Summary:
- **Description**: Translates a Zeek telnet.log to OCSF Network Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.4.0/classes/network_activity](https://schema.ocsf.io/1.4.0/classes/network_activity)  
  - [https://docs.zeek.org/en/master/logs/telnet.html](https://docs.zeek.org/en/master/logs/telnet.html)
  - [https://docs.zeek.org/en/master/scripts/base/protocols/login/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/login/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| `metadata.version` | "1.4.0" | String |
| `category_uid` | 4 | Integer |
| `class_uid` | 4001 | Integer |
| `metadata.product.name` | "Zeek" | String |
| `metadata.product.vendor_name` | "Zeek" | String |
| `severity_id` | 1 | Integer |
| `activity_id` | 6 | Integer |
| `activity_name` | "Traffic" | String |
| `connection_info.protocol_name` | "TELNET" | String |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| `time` | `ts` | Session initiation timestamp | Convert to epoch. Type: `timestamp_t` (Long) |
| `start_time` | `ts` | Session start time | Convert to epoch. Type: `timestamp_t` (Long) |
| `metadata.logged_time` | `_write_ts` | Log write time | Convert to epoch. Type: `timestamp_t` (Long) |
| `metadata.loggers[].name` | `_system_name` | Logging subsystem | Type: `string_t` |
| `metadata.log_name` | `_path` | Log identifier | Type: `string_t` |
| `metadata.uid` | `uid` | Unique ID for the connection. | Type: `string_t` |
| `src_endpoint.ip` | `id.orig_h` | Client IP | Type: `ip_t` |
| `src_endpoint.port` | `id.orig_p` | Client port | Type: `port_t` (Integer) |
| `dst_endpoint.ip` | `id.resp_h` | Server IP | Type: `ip_t` |
| `dst_endpoint.port` | `id.resp_p` | Server port | Type: `port_t` (Integer) |
| `raw_data` | `data` | Initial payload | Type: `byte_stream_t` |
| `app_name` | `_path` | Protocol identifier | Fixed value "telnet". Type: `string_t` |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| `type_uid` | `activity_id` | Event type ID | Calculate as `(4001 * 100) + 6 = 400106` |
| `status_id` | `login_success` | Auth outcome | `T→1` (Success), `F→2` (Failure), else `0` (Unknown) |
| `auth_info.credential` | `password` | Auth secret | Only map if plaintext capture enabled. Type: `credential_t` |

### Unmapped:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| `extension.terminal` | `terminal_type` | Client terminal | Requires custom OCSF extension |
| `network_traffic.env_vars` | `environ_vars` | Telnet ENV vars | No native OCSF 1.4.0 equivalent |
| `observables[].value` | `client_version` | Client software | Could map to `software.name` observable |
| `evidence.session_flags` | `tn3270` | Terminal type | Requires evidence object expansion |
| `auth_info.method` | `login_success` | Auth mechanism | Insufficient protocol-level detail |