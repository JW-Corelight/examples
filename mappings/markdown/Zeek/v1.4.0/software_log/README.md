# Event Dossier: Zeek software.log
### Summary:
- **Description**: Maps Zeek software detection events to OCSF Software Inventory Info class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/software_inventory_info
  - https://docs.zeek.org/en/master/logs/software.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 5              | Integer    |
| `class_uid`                   | 5020           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Software detection timestamp               | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `device.ip`                   | `host`                  | Host IP address                            | Type: ip_t                 |
| `device.port`                 | `host_p`                | Host port                                  | Type: port_t               |
| `package.name`                | `name`                  | Software name                              |                            |
| `package.type`                | `software_type`         | Software type                              |                            |

### Version mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `package.version`             | `unparsed_version`      | String      | Full version string        |
| `package.version_info.major`  | `version.major`         | Integer     | Major version number       |
| `package.version_info.minor`  | `version.minor`         | Integer     | Minor version number       |
| `package.version_info.patch`  | `version.minor2`        | Integer     | Patch version number       |
| `package.version_info.build`  | `version.minor3`        | Integer     | Build version number       |
| `package.version_info.additional` | `version.addl`      | String      | Additional version info     |
