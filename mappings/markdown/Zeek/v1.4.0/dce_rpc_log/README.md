# Event Dossier: Zeek dce_rpc.log

### Summary:
- **Description**: Translates a Zeek dce_rpc.log to OCSF SMB Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/smb_activity](https://schema.ocsf.io/1.3.0/classes/smb_activity)  
  - [https://docs.zeek.org/en/master/logs/dce_rpc.html](https://docs.zeek.org/en/master/logs/dce_rpc.html)
  - [https://docs.zeek.org/en/master/scripts/base/protocols/dce-rpc/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/dce-rpc/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4006 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 3 | Integer |
| activity_name | "RPC" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the DCE/RPC call occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the DCE/RPC call occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The client's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The client's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The server's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The server's port number. | Type is port_t (Integer). |
| share | named_pipe | Named pipe path used for the RPC call. | Strip "\\PIPE\\" prefix if present. Type is String. |
| dce_rpc.endpoint | endpoint | Service endpoint name. | Service identifier. Type is String. |
| dce_rpc.operation | operation | RPC operation name. | Method or function being called. Type is String. |
| dce_rpc.rtt | rtt | Round trip time in seconds. | Time between request and response. Type is Double. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| type_uid | activity_id | Type identifier. | Calculate as (class_uid * 100) + activity_id = 400603. Type is Integer. |
| status_id | rtt | Success of the operation. | If rtt present, "1" (Success), otherwise "0" (Unknown). Type is Integer. |
| dce_rpc.interface_uuid | endpoint | Interface UUID. | Extract UUID from endpoint if present in format. Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | context_id | Context ID for the DCE/RPC call. | Integer identifier for this specific call. Type is Integer. |
| unmapped | opnum | Operation number for the endpoint function call. | Numeric identifier for the operation. Type is Integer. |
| unmapped | fid | File ID, if this DCE/RPC message was sent over SMB. | Present when the transport is SMB. Type is Integer. |
| unmapped | arg | Argument data provided to the call. | May contain sensitive data. Type is String. |
| unmapped | interfaces | List of interface UUIDs seen for this session. | Type is Array of String. |
| unmapped | auth_type | Authentication method used for the session. | Type is String. |