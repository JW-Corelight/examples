# Event Dossier: Zeek software.log

### Summary:
- **Description**: Translates a Zeek software.log to OCSF Software Inventory Info class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/software_inventory_info](https://schema.ocsf.io/1.3.0/classes/software_inventory_info)  
  - [https://docs.zeek.org/en/master/logs/software.html](https://docs.zeek.org/en/master/logs/software.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 5 | Integer |
| class_uid | 5020 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when software was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when software was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| device.ip | host | Host IP address where software was observed. | Type is ip_t. |
| device.port | host_p | Host port where software was observed. | Type is port_t (Integer). |
| package.name | name | Software product name. | Type is String. |
| package.type | software_type | Category of software. | Examples include "HTTP::SERVER", "HTTP::BROWSER", etc. Type is String. |
| package.version | unparsed_version | Full version string as observed. | Type is String. |
| package.version_info.major | version.major | Major version number. | Type is Integer. |
| package.version_info.minor | version.minor | Minor version number. | Type is Integer. |
| package.version_info.patch | version.minor2 | Patch version number. | Type is Integer. |
| package.version_info.build | version.minor3 | Build version number. | Type is Integer. |
| package.version_info.additional | version.addl | Additional version info. | May include alpha/beta status or other qualifiers. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| device.type_id | software_type | Category of software. | Map software_type to device type: "HTTP::SERVER" → 3 (Server), "SSH::SERVER" → 3 (Server), "HTTP::BROWSER" → 1 (Workstation), else 0 (Unknown). Type is Integer. |
| package.vendor | name | Software product name. | Extract vendor from name if available (e.g., "Microsoft Internet Explorer" → "Microsoft"). Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | url | URL where software information was discovered. | Only present for HTTP-based discovery. Type is String. |
| unmapped | detection_source | How the software was detected. | Source of detection (e.g., "HTTP::SERVER" header). Type is String. |
| unmapped | host_p_type | Protocol type of host_p. | Usually "tcp" for HTTP, SSH, etc. Type is String. |