# Event Dossier: Zeek ldap_search.log

### Summary:
- **Description**: Translates a Zeek ldap_search.log to OCSF Authentication class.  
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
| activity_id | 6 | Integer |
| activity_name | "Search" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the LDAP search occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the LDAP search occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. Client performing the search. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. LDAP server. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| connection_info.protocol_name | proto | Transport protocol. | Usually "tcp". Type is String. |
| message | diagnostic_message | Error or status message. | Response message from server. Type is String. |
| auth_protocol_ver | version | LDAP protocol version. | Integer converted to string (usually "3"). Type is String. |
| service.resource.name | base_object | LDAP search base DN. | Distinguished Name for search base. Type is String. |
| service.resource.query | filter | LDAP search filter. | Filter expression for the search. Type is String. |
| service.resource.type | scope | LDAP search scope. | May be "base", "one", or "sub". Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| status_id | result | Search result. | If "success" then "1" (Success), else "2" (Failure). Type is Integer. |
| status_detail | result_count | Number of search results. | Format as "Results found: {result_count}". Type is String. |
| service.resource.params | attributes | Requested attributes. | If present, convert array to comma-separated string. Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | message_id | LDAP message identifier. | Integer uniquely identifying the LDAP message. Type is Integer. |
| unmapped | time_limit | Time limit for the search. | Maximum time in seconds for search. Type is Integer. |
| unmapped | size_limit | Size limit for the search. | Maximum number of results to return. Type is Integer. |
| unmapped | deref | Dereference policy. | How to handle alias dereferencing. Type is String. |
| unmapped | types_only | Whether to return attribute types only. | Boolean indicating if values should be excluded. Type is Boolean. |