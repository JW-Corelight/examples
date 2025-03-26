# Event Dossier: Zeek notice.log

### Summary:
- **Description**: Translates a Zeek notice.log to OCSF Detection Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/detection_finding](https://schema.ocsf.io/1.3.0/classes/detection_finding)  
  - [https://docs.zeek.org/en/master/logs/weird-and-notice.html](https://docs.zeek.org/en/master/logs/weird-and-notice.html)  
  - [https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/notice/main.zeek](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/notice/main.zeek)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2004 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when notice occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when notice occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp when record was written. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of system generating record. |  |
| metadata.log_name | _path | Log name ("notice"). |  |
| metadata.uid | uid | Unique ID for the connection. | May be empty if not associated with a specific connection. |
| evidences[].src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. May be empty if not associated with a specific connection. |
| evidences[].src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). May be empty if not associated with a specific connection. |
| evidences[].dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. May be empty if not associated with a specific connection. |
| evidences[].dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). May be empty if not associated with a specific connection. |
| finding_info.title | note | Notice::Type classification. | Categorization of the notice (e.g., "SSH::Password_Guessing"). Type is String. |
| message | msg | Human-readable notice message. | Descriptive message explaining the notice. Type is String. |
| severity | severity.name | Textual severity level. | If present, provides named severity level. Type is String. |
| severity_id | severity.level | Numeric severity identifier. | Maps to OCSF severity levels. Type is Integer. |
| observables[].value | sub | Additional context/observables. | Supplementary data relevant to the notice. Type is String. |
| connection_info.protocol_name | proto | Transport protocol. | Protocol related to the notice (e.g., "tcp", "udp"). Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| status_id | suppress_for | Suppression duration. | If value > 0 then "3" (Suppressed), else "1" (New). Type is Integer. |
| status_detail | actions | Actions to take for this notice. | Convert action list to human text, join actions with semicolons. Type is String. |
| finding_info.data_sources[] | peer_descr | Peer description. | If present, add as data source. Type is Array of String. |
| finding_info.policy_id | policy | Policy associated with the notice. | If present, maps to policy identifier. Type is String. |
| evidences[].file.uid | fuid | File UID associated with notice. | Only if notice is file-related. Type is String. |
| evidences[].file.mime_type | file_mime_type | MIME type of associated file. | Only if notice is file-related. Type is String. |
| evidences[].file.name | file_desc | Description of associated file. | Only if notice is file-related. Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | remote_location.country_code | Country code for remote address. | ISO country code for geolocation. Type is String. |
| unmapped | remote_location.region | Region for remote address. | Geographic region. Type is String. |
| unmapped | remote_location.city | City for remote address. | Geographic city. Type is String. |
| unmapped | remote_location.latitude | Latitude for remote address. | Geographic latitude. Type is Float. |
| unmapped | remote_location.longitude | Longitude for remote address. | Geographic longitude. Type is Float. |
| unmapped | dropped | Whether Zeek dropped the connection. | Only present if action includes "drop". Type is Boolean. |
| unmapped | n | The number of times this notice has been seen. | Count of occurrences. Type is Integer. |