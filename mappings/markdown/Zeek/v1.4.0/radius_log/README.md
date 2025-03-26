# Event Dossier: Zeek radius.log

### Summary:
- **Description**: Translates a Zeek radius.log to OCSF Authentication class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/authentication](https://schema.ocsf.io/1.3.0/classes/authentication)  
  - [https://docs.zeek.org/en/master/logs/radius.html](https://docs.zeek.org/en/master/logs/radius.html)  
  - [https://docs.zeek.org/en/master/scripts/base/protocols/radius/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/radius/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 3 | Integer |
| class_uid | 3002 | Integer |
| auth_protocol_id | 10 | Integer |
| auth_protocol | "RADIUS" |  |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the authentication event occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the authentication event occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| user.name | username | Authentication username. |  |
| message | reply_msg | Server reply message. |  |
| duration | ttl | Authentication time-to-live. | Convert to milliseconds. Type is Integer. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| status_id | result | Authentication result. | If "success" then "1" (Success), if "failed" then "2" (Failure), else "0" (Unknown). Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| observables[].value | mac | Client MAC address. |
| observables[].value | framed_addr | Assigned IP address. |
| observables[].value | tunnel_client | Tunnel client endpoint. |