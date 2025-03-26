# Event Dossier: Zeek weird.log

### Summary:
- **Description**: Translates a Zeek weird.log to OCSF Detection Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/detection_finding](https://schema.ocsf.io/1.3.0/classes/detection_finding)  
  - [https://docs.zeek.org/en/master/logs/weird-and-notice.html](https://docs.zeek.org/en/master/logs/weird-and-notice.html)  
  - [https://docs.zeek.org/en/master/scripts/base/frameworks/notice/weird.zeek](https://docs.zeek.org/en/master/scripts/base/frameworks/notice/weird.zeek)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2004 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the weird event occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the weird event occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. | May be empty if not associated with a specific connection. |
| evidences[].src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. May be empty if not associated with a specific connection. |
| evidences[].src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). May be empty if not associated with a specific connection. |
| evidences[].dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. May be empty if not associated with a specific connection. |
| evidences[].dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). May be empty if not associated with a specific connection. |
| finding_info.title | name | Weird type name. | A short descriptive name of the weird condition. Type is String. |
| finding_info.data_sources[] | source | Protocol analyzer or source component name. | Zeek component that generated the weird. Type is Array of String. |
| message | addl | Additional context for the weird event. | Supplementary information explaining the weird. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| status_id | notice | Elevated to notice status flag. | If true then "2" (In Progress), if false then "1" (New). Type is Integer. |
| severity_id | name | Weird type name. | Special case mappings for specific high-severity weirds: If contains "attack" or "exploit" then "3" (Medium), if contains "overflow" or "injection" then "4" (High), else "1" (Informational). Type is Integer. |
| finding_info.count | num_weirds | The number of times similar weirds were detected. | If num_weirds exists, set finding_info.count to this value. Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | peer | Zeek cluster node identifier. | Name of the Zeek node that generated this log. Type is String. |
| unmapped | analyzer_id | Unique analyzer instance ID. | Identifies the specific analyzer instance. Type is String. |
| unmapped | suppress_for | How long future weirds of this type will be suppressed. | Duration in seconds. Type is Float. |
| unmapped | weird_id | Unique ID for this specific weird instance. | May be used for correlation with other logs. Type is String. |