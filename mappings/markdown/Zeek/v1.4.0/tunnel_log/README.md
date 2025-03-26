# Event Dossier: Zeek tunnel.log

### Summary:
- **Description**: Translates a Zeek tunnel.log to OCSF Tunnel Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/tunnel_activity](https://schema.ocsf.io/1.3.0/classes/tunnel_activity)  
  - [https://docs.zeek.org/en/master/logs/tunnel.html](https://docs.zeek.org/en/master/logs/tunnel.html)  
  - [https://docs.zeek.org/en/master/scripts/base/frameworks/tunnels/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/frameworks/tunnels/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4014 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the tunnel activity occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the tunnel activity occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| protocol_name | tunnel_type | Type of tunnel protocol. | Strip "Tunnel::" prefix. Examples include "GRE", "IP", "AYIYA", etc. Type is String. |
| connection_info.protocol_name | tunnel_type | Type of tunnel protocol. | Same as protocol_name, but preserves for connection info. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| activity_id | action | Tunnel activity type. | If "DISCOVER" then "1" (Open), if "EXPIRE" then "2" (Close), else "0" (Unknown). Type is Integer. |
| type_uid | activity_id | Calculated type identifier. | Calculate as (class_uid * 100) + activity_id = 401X00, where X is the activity_id. Type is Integer. |
| tunnel_stats.duration | ts + action | Implied duration based on action. | If action = "EXPIRE", calculate duration based on referenced tunnel start time. Otherwise null. Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | encapsulating | If this was an encapsulating tunnel, a connection UID is provided. | Connection UID of the encapsulating tunnel, if any. Type is String. |
| unmapped | inner_vlan | The inner VLAN ID, if present. | For VLAN-in-VLAN tunneling. Type is Integer. |
| unmapped | outer_vlan | The outer VLAN ID, if present. | For VLAN tunneling. Type is Integer. |
| unmapped | next_proto | The protocol encapsulated by this tunnel. | Numeric protocol identifier. Type is Integer. |