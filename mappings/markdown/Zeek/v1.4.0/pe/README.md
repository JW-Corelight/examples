# Event Dossier: Zeek pe.log

### Summary:
- **Description**: Translates a Zeek pe.log to OCSF Data Security Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/data_security_finding](https://schema.ocsf.io/1.3.0/classes/data_security_finding)  
  - [https://docs.zeek.org/en/master/scripts/policy/misc/pe.zeek.html](https://docs.zeek.org/en/master/scripts/policy/misc/pe.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2006 | Integer |
| activity_id | 1 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the PE file was analyzed. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the PE file was analyzed. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| file.created_time | compile_ts | PE compilation timestamp. | Convert to epoch value. Type is timestamp_t (Long). |
| file.xattributes.is_64bit | is_64bit | Indicates if the PE file is for a 64-bit architecture. | Type is Boolean. |
| file.xattributes.aslr | uses_aslr | Indicates if ASLR is implemented in the PE file. | Type is Boolean. |
| file.xattributes.dep | uses_dep | Indicates if Data Execution Prevention is implemented. | Type is Boolean. |
| file.xattributes.seh | uses_seh | Indicates if Structured Exception Handling is implemented. | Type is Boolean. |
| file.xattributes.sections | section_names | Names of the sections in the PE file. | Type is Array of String. |
| file.xattributes.certs | has_cert_table | Indicates if a certificate table is present in the PE file. | Type is Boolean. |
| file.xattributes.debug | has_debug_data | Indicates if debug data is present in the PE file. | Type is Boolean. |
| file.is_system | subsystem | Windows subsystem type. | Convert from code to Boolean for system status. |
| file.xattributes.imports | has_import_table | Indicates if an import table is present in the PE file. | Type is Boolean. |
| file.xattributes.exports | has_export_table | Indicates if an export table is present in the PE file. | Type is Boolean. |
| file.xattributes.integrity | uses_code_integrity | Indicates if code integrity is implemented. | Type is Boolean. |
| file.uid | id | Unique identifier for the file. | Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | machine | Target machine architecture. |
| unmapped | os | Required operating system version. |