# Event Dossier: Zeek ldap.log

### Summary:
- **Description**: Translates a Zeek ldap.log to OCSF Authentication class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/authentication](https://schema.ocsf.io/1.3.0/classes/authentication)  
  - [https://docs.zeek.org/en/master/logs/ldap.html](https://docs.zeek.org/en/master/logs/ldap.html)  
  - [https://docs.zeek.org/en/master/scripts/base/protocols/ldap/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/ldap/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 3 | Integer |
| class_uid | 3002 | Integer |
| auth_protocol_id | 99 | Integer |
| auth_protocol | "LDAP" |  |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the authentication occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the authentication occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| connection_info.protocol_name | proto | Transport protocol. | Usually "tcp". |
| message | diagnostic_message | Error or status message from the LDAP server. | Present when authentication fails. |
| user.name | name | Distinguished name provided in the LDAP bind request. | Only present for "bind" operations. |
| connection_info.version | version | LDAP protocol version. | Integer representing the LDAP version (usually 3). |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| status_id | result | Authentication result. | If "success" then "1" (Success), if "failed" then "2" (Failure), else "0" (Unknown). Type is Integer. |
| auth_factors | opcode | Authentication method. | If "bind simple" then [1] (Password), if "bind SASL" then [2] (Certificate/token), else [0] (Unknown). Type is Array of Integer. |
| activity_name | opcode | Operation performed in this LDAP message. | Set to the operation name (e.g., "bind", "search", "modify"). Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | message_id | LDAP message identifier. | Integer uniquely identifying the LDAP message. |
| unmapped | object | LDAP object identifier. | Distinguished name of the target object. |
| unmapped | argument | Additional arguments for the LDAP operation. | Content varies by operation type. |
| unmapped | controls | LDAP control extensions. | Array of control OIDs and their values. |