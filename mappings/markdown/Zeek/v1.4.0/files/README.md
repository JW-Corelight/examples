# Event Dossier: Zeek files.log

### Summary:
- **Description**: Translates a Zeek files.log to OCSF Data Security Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/data_security_finding](https://schema.ocsf.io/1.3.0/classes/data_security_finding)  
  - [https://docs.zeek.org/en/master/logs/files.html](https://docs.zeek.org/en/master/logs/files.html)  
  - [https://corelight.blog/zeek-file-analysis](https://corelight.blog/zeek-file-analysis)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2006 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when file was first seen. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when file was first seen. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp when log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| file.uid | fuid | Unique file identifier. | Unique ID used to track this file across logs. Type is String. |
| file.name | filename | Original filename from the source. | May not be present for all file transfers. Type is String. |
| file.mime_type | mime_type | Detected MIME type of the file. | Based on content analysis, not filename. Type is String. |
| file.size | total_bytes | Complete file size in bytes. | May be estimated if file transfer was not completed. Type is Integer. |
| file.hashes[].algorithm_id | md5 | MD5 message digest algorithm. | If md5 present, add with algorithm_id=1. |
| file.hashes[].value | md5 | MD5 digest of file contents. | Hexadecimal string representation of hash. |
| file.hashes[].algorithm_id | sha1 | SHA1 message digest algorithm. | If sha1 present, add with algorithm_id=3. |
| file.hashes[].value | sha1 | SHA1 digest of file contents. | Hexadecimal string representation of hash. |
| file.hashes[].algorithm_id | sha256 | SHA256 message digest algorithm. | If sha256 present, add with algorithm_id=4. |
| file.hashes[].value | sha256 | SHA256 digest of file contents. | Hexadecimal string representation of hash. |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| connection_info.protocol_name | source | File transfer protocol. | Examples: "HTTP", "FTP", "SMTP", etc. Type is String. |
| file.entropy | entropy | Information entropy calculation of file. | Value between 0-8. Higher values indicate higher randomness. Type is Float. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| file_result.path | extracted | File extraction path. | If file extraction occurred, store location. Type is String. |
| status_id | timedout | Analysis timeout indicator. | If true then "3" (Suppressed), if false then "1" (New). Type is Integer. |
| observables[].value | conn_uids | Connection UIDs associated with file. | If multiple connections present, include as "connection_id" observables. Type is Array of String. |
| file.xattributes.is_orig | is_orig | File transfer direction flag. | If true, file was sent by the connection originator. Type is Boolean. |
| file.integrity_level | seen_bytes | Number of file bytes seen. | If seen_bytes < total_bytes, "2" (Partial), else "1" (Complete). Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | depth | File nesting depth in transfer. | 1 for non-nested files, >1 for nested ones (e.g., files in ZIP). Type is Integer. |
| unmapped | analyzers | File analysis types performed. | List of analyzers that processed this file. Type is Array of String. |
| unmapped | local_orig | Network locality flag. | True if file originator is a local IP. Type is Boolean. |
| unmapped | duration | How long file was processed. | Duration of file analysis. Type is Float. |
| unmapped | overflow_bytes | Bytes overflowing reassembly buffer. | Non-zero indicates incomplete analysis. Type is Integer. |
| unmapped | missing_bytes | Number of bytes missing in reassembly. | Non-zero indicates gaps in file content. Type is Integer. |