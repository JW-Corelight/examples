# Event Dossier: Zeek dpd.log

### Summary:
- **Description**: Translates a Zeek dpd.log to OCSF Detection Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/detection_finding](https://schema.ocsf.io/1.3.0/classes/detection_finding)  
  - [https://docs.zeek.org/en/master/logs/dpd.html](https://docs.zeek.org/en/master/logs/dpd.html)  
  - [https://docs.zeek.org/en/master/scripts/base/frameworks/dpd/main.zeek](https://docs.zeek.org/en/master/scripts/base/frameworks/dpd/main.zeek)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2004 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 2 | Integer |
| activity_id | 1 | Integer |
| activity_name | "Protocol Violation" | Type is String. |
| finding_info.category | "Configuration" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when protocol analysis failure occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when protocol analysis failure occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp when record was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of system generating record. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| evidences[].src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| evidences[].src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| evidences[].dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| evidences[].dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| finding_info.title | analyzer | Protocol analyzer name. | The analyzer that encountered the protocol violation. Type is String. |
| message | failure_reason | Analysis failure description. | Explanation of why protocol analysis failed. Type is String. |
| connection_info.protocol_name | proto | Transport protocol. | Usually "tcp" or "udp". Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| observables[].value | packet_segment | Packet payload data. | If present, add as observable with type="packet_data" and tag="sample". Type is String. |
| finding_info.description | packet_segment | Packet payload data. | If present, format as "Protocol violation in {analyzer}: {failure_reason}. Packet segment: {packet_segment}". If not present, use "Protocol violation in {analyzer}: {failure_reason}". Type is String. |
| finding_info.labels[] | failure_reason | Analysis failure description. | Extract keywords from failure reason: Contains "unexpected" → "Unexpected Data", contains "missing" → "Missing Fields", contains "invalid" → "Invalid Format", else "Protocol Error". Type is Array of String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | violator | Endpoint causing the protocol violation. | "ORIG" for originator, "RESP" for responder. Type is String. |
| unmapped | analyzer_id | Unique analyzer instance ID. | Identifies the specific analyzer instance. Type is String. |