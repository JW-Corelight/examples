# Event Dossier: Zeek rfb.log

### Summary:
- **Description**: Translates a Zeek rfb.log to OCSF Network Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/network_activity](https://schema.ocsf.io/1.3.0/classes/network_activity)  
  - [https://docs.zeek.org/en/master/logs/rfb.html](https://docs.zeek.org/en/master/logs/rfb.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4001 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the RFB event occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the RFB event occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The client's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The client's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The server's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The server's port number. | Type is port_t (Integer). |
| app_name | desktop_name | Name of the shared desktop or VNC server. | Type is String. |
| remote_display.physical_width | width | Width of the VNC desktop in pixels. | Type is Integer. |
| remote_display.physical_height | height | Height of the VNC desktop in pixels. | Type is Integer. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| connection_info.client_version | client_major_version, client_minor_version | Client RFB protocol version. | Format as "{client_major_version}.{client_minor_version}". Type is String. |
| connection_info.server_version | server_major_version, server_minor_version | Server RFB protocol version. | Format as "{server_major_version}.{server_minor_version}". Type is String. |
| status_id | auth | Authentication status. | If true then "1" (Success), if false then "2" (Failure), else "0" (Unknown). Type is Integer. |
| connection_info.protocol | share_flag | Sharing mode of the connection. | If true then "shared", if false then "exclusive". Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | authentication_method | Authentication method used for VNC. | Integer code representing the auth method (0=None, 1=VNC, 2=Other). |
| unmapped | security_type | Security type being used with RFB/VNC. | Security type identifier. |
| unmapped | security_types | All security types offered. | Array of security type identifiers. |
| unmapped | auth_success | Was the client authorization successful? | Boolean indicator for auth success, more detailed than 'auth'. |