# Event Dossier: Zeek known_certs.log
### Summary:
- **Description**: Maps Zeek known certificate observations to OCSF Device Inventory Info class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/device_inventory_info
  - https://docs.zeek.org/en/master/logs/known_certs.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 5              | Integer    |
| `class_uid`                   | 5001           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `activity_id`                 | 2              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Certificate first seen timestamp           | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `kuid`                  | Observation unique ID                      |                            |
| `device.ip`                   | `host_ip`               | Host IP address                            | Type: ip_t                 |
| `device.port`                 | `port_num`              | Server listening port                      | Type: port_t               |
| `duration`                    | `duration`              | Observation duration                       | Convert to milliseconds    |
| `device.name`                 | `subject`               | Certificate subject name                    |                            |

### Certificate mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `device.certificates[].hash`   | `hash`                  | String      | SHA1 hash                  |
| `device.certificates[].serial` | `serial`                | String      | Certificate serial number   |
| `device.certificates[].subject`| `subject`               | String      | Certificate subject         |
| `device.certificates[].issuer` | `issuer_subject`        | String      | Certificate issuer          |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `observables[].value`         | `host_vlan`             | vlan        | Host VLAN ID               |
| `observables[].value`         | `host_inner_vlan`       | vlan        | Host inner VLAN ID         |
