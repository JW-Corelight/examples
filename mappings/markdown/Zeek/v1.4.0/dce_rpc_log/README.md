# Event Dossier: Zeek dce_rpc.log

### Summary:
- **Description**: Translates a Zeek dce_rpc.log to OCSF SMB Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.4.0/classes/smb_activity](https://schema.ocsf.io/1.4.0/classes/smb_activity)  
  - [https://docs.zeek.org/en/master/logs/dce_rpc.html](https://docs.zeek.org/en/master/logs/dce_rpc.html)
  - [https://docs.zeek.org/en/master/scripts/base/protocols/dce-rpc/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/dce-rpc/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| `metadata.version` | "1.4.0" | String |
| `category_uid` | 4 | Integer |
| `class_uid` | 4006 | Integer |
| `metadata.product.name` | "Zeek" | String |
| `metadata.product.vendor_name` | "Zeek" | String |
| `severity_id` | 1 | Integer |
| `activity_id` | 3 | Integer |
| `activity_name` | "RPC" | String |
| `connection_info.protocol_name` | "DCE/RPC" | String |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| `time` | `ts` | DCE/RPC call timestamp | Convert to epoch. Type: `timestamp_t` (Long) |
| `start_time` | `ts` | Call initiation time | Convert to epoch. Type: `timestamp_t` (Long) |
| `metadata.logged_time` | `_write_ts` | Log write time | Convert to epoch. Type: `timestamp_t` (Long) |
| `metadata.loggers[].name` | `_system_name` | Logging subsystem | Type: `string_t` |
| `metadata.log_name` | `_path` | Log identifier | Type: `string_t` |
| `metadata.uid` | `uid` | Unique ID for the connection. | Type: `string_t` |
| `src_endpoint.ip` | `id.orig_h` | Client IP | Type: `ip_t` |
| `src_endpoint.port` | `id.orig_p` | Client port | Type: `port_t` (Integer) |
| `dst_endpoint.ip` | `id.resp_h` | Server IP | Type: `ip_t` |
| `dst_endpoint.port` | `id.resp_p` | Server port | Type: `port_t` (Integer) |
| `dce_rpc.operation` | `operation` | RPC method called | Type: `string_t` |
| `dce_rpc.rtt` | `rtt` | Round-trip time | Convert to milliseconds. Type: `double_t` |
| `share` | `named_pipe` | SMB pipe path | Remove `\PIPE\` prefix. Type: `string_t` |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| `activity_id` | `operation` | RPC activity type | Map "Bind" → 8 (Session), "Request" → 1 (Execute). Else 0 (Unknown) |
| `activity_name` | `activity_id` | Activity label | Derived from mapped `activity_id` value |
| `type_uid` | `activity_id` | Event type ID | Calculate as `(4006 * 100) + 3 = 400603`. |
| `dce_rpc.interface_uuid` | `endpoint` | Service interface | Extract UUID patterns (8-4-4-4-12 format). Type: `uuid_t` |
| `status_id` | `rtt` | Operation success | `rtt > 0 → 1` (Success), `null → 0` (Unknown). Confidence: Medium (false negatives possible) |
| `file.uid` | `fid` | SMB file handle | Only map when `fid` exists. Type: `string_t` |
| `auth_info.auth_protocol` | `auth_type` | Auth mechanism | Map "NT LAN Manager" → `3`, "Kerberos" → `4`. Type: `integer_t` |

### Unmapped:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| `extension.context` | `context_id` | Call identifier | Requires custom OCSF extension |
| `observables[].value` | `opnum` | Operation code | Map as `observables[].type_id: 67` (Other) |
| `evidence.artifacts` | `arg` | Call arguments | Sensitive data excluded per OCSF policy |
| `dce_rpc.interfaces` | `interfaces` | UUID list | No array support in OCSF 1.4.0 `dce_rpc` object |