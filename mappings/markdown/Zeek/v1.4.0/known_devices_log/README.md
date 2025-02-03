# Event Dossier: Zeek known_devices.log
### Summary:
- **Description**: Maps Zeek known device observations to OCSF Device Inventory Info class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/device_inventory_info
  - https://docs.zeek.org/en/master/logs/known_devices.html

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
| `time`                        | `ts`                    | Device first seen timestamp                | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `kuid`                  | Observation unique ID                      |                            |
| `device.ip`                   | `host_ip`               | Host IP address                            | Type: ip_t                 |
| `device.mac_addr`             | `mac`                   | Device MAC address                         |                            |
| `device.vendor`               | `vendor_mac`            | Device manufacturer                        |                            |
| `duration`                    | `duration`              | Observation duration                       | Convert to milliseconds    |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `observables[].value`         | `host_vlan`             | vlan        | Host VLAN ID               |
| `observables[].value`         | `host_inner_vlan`       | vlan        | Host inner VLAN ID         |
| `observables[].value`         | `protocols[]`           | protocol    | Observed protocols          |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `num_conns`              | Number of observed connections                |
| `long_conns`             | Count of long connections                     |
| `annotations`            | Observation annotations                       |
| `last_active_session`    | Last seen session                            |
| `last_active_interval`   | Last seen interval                           |
