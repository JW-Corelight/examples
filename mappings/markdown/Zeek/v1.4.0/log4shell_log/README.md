# Event Dossier: Zeek log4shell.log

### Summary:
- **Description**: Translates a Zeek log4shell.log to OCSF Detection Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/detection_finding](https://schema.ocsf.io/1.3.0/classes/detection_finding)  
  - [https://docs.zeek.org/en/master/logs/log4shell.html](https://docs.zeek.org/en/master/logs/log4shell.html)  
  - [https://github.com/corelight/CVE-2021-44228](https://github.com/corelight/CVE-2021-44228)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2004 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 4 | Integer |
| activity_id | 1 | Integer |
| finding_info.category | "Vulnerability" | Type is String. |
| finding_info.cve.id | "CVE-2021-44228" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the Log4Shell attempt was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the Log4Shell attempt was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. Source of the potential attack. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. Target of the potential attack. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| finding_info.title | name | HTTP header field name containing the exploit. | Which HTTP field contained the JNDI exploit. Type is String. |
| message | value | HTTP header field value. | The actual payload containing the JNDI exploit string. Type is String. |
| http_request.url | http_uri | HTTP request URI. | Path of HTTP request containing the exploit. Type is String. |
| connection_info.protocol_name | protocol | Transport protocol. | Usually "HTTP" or "LDAP". Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| status_id | matched_value | Log4Shell attempt confirmed. | If true then "2" (In Progress), else "1" (New). Type is Integer. |
| finding_info.confidence | matched_value | Confidence in the detection. | If true then "3" (High), else "2" (Medium). Type is Integer. |
| finding_info.description | uri | Complete JNDI URI. | If present, format as "Log4Shell exploit attempt using JNDI URI: {uri}". Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| observables[].value | target_host | JNDI target host. | Hostname or IP in the JNDI lookup. Type is String. |
| observables[].value | target_port | JNDI target port. | Port specified in the JNDI lookup. Type is port_t (Integer). |
| observables[].value | uri | Complete JNDI URI. | Full URI from the exploit attempt. Type is String. |
| observables[].value | stem | Base JNDI hostname. | Root domain of the attack infrastructure. Type is String. |
| unmapped | is_base64 | Whether the exploit is base64 encoded. | Boolean indicating obfuscation technique. Type is Boolean. |
| unmapped | is_nested | Whether the exploit contains nested references. | Boolean indicating complex exploit structure. Type is Boolean. |