# Event Dossier: Zeek intel.log

### Summary:
- **Description**: Translates a Zeek intel.log to OCSF Detection Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/detection_finding](https://schema.ocsf.io/1.3.0/classes/detection_finding)  
  - [https://docs.zeek.org/en/master/frameworks/intel.html](https://docs.zeek.org/en/master/frameworks/intel.html)  
  - [https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2004 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 3 | Integer |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the intelligence match occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the intelligence match occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| evidences[].src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| evidences[].src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| evidences[].dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| evidences[].dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| finding_info.data_sources[] | sources | Intelligence sources that identified the indicator. | Type is Array of String. |
| finding_info.labels[] | matched | Labels associated with the triggered indicator. | Type is Array of String. Added from Intel::Item. |
| finding_info.remediation | policy | Action applied when this intelligence was discovered. | Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| observables[].type_id | seen.indicator_type | Type of data that triggered the match. | Map Intel::Type to OCSF Observable type_id. For example: "ADDR" → 4 (IP), "DOMAIN" → 1 (Hostname), "URL" → 3 (URL), "SOFTWARE" → 7 (Software), "EMAIL" → 6 (Email), "USER_NAME" → 2 (Username), "FILE_HASH" → 5 (File Hash), "FILE_NAME" → 11 (Filename), "CERT_HASH" → 8 (Certificate). Type is Integer. |
| observables[].value | seen.indicator | The actual indicator that was matched. | Value format depends on indicator_type. |
| observables[].location | seen.where | Context where the indicator was discovered. | Maps to observable location context. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| evidences[].file.uid | fuid | File unique ID. | Type is String. Present when indicator was found in a file. |
| evidences[].file.mime_type | file_mime_type | File MIME type. | Type is String. Present when indicator was found in a file. |
| evidences[].file.desc | file_desc | File description. | Type is String. Present when indicator was found in a file. |
| unmapped | conn | Connection info if the intel hit is related to a connection. | Contains connection metadata fields. |