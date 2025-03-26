# Event Dossier: Zeek smb_mapping.log

### Summary:
- **Description**: Translates a Zeek smb_mapping.log to OCSF SMB Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/smb_activity](https://schema.ocsf.io/1.3.0/classes/smb_activity)  
  - [https://docs.zeek.org/en/master/logs/smb_mapping.html](https://docs.zeek.org/en/master/logs/smb_mapping.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4006 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 99 | Integer |
| activity_name | "Share Map" |  |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the share mapping occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the share mapping occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The client's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The client's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The server's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The server's port number. | Type is port_t (Integer). |
| share | path | Full UNC path to the share being accessed. | Extract share name from path. Type is String. |
| share_type | share_type | Type of share (DISK, PIPE, PRINTER, etc.). | SMB share type descriptor. Type is String. |
| remote_service | service | Type of resource being accessed. | Describes the service associated with this mapping. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| share_type_id | share_type | Share type identifier. | If "DISK" then "1" (File), if "PIPE" then "2" (Pipe), if "PRINTER" then "3" (Print), if "COMM" then "4" (Communications), if "IPC" then "5" (IPC), else "99" (Other). Type is Integer. |
| status_id | status | Connection status. | If present and not "SUCCESS", "2" (Failure), else "1" (Success). Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | native_file_system | File system type of the share. | String identifying the underlying filesystem (NTFS, FAT, etc.). |
| unmapped | tree_id | SMB tree ID. | Identifier for this connection within the SMB session. |
| unmapped | share_access | Share access flags. | Bitfield indicating read/write/admin privileges. |