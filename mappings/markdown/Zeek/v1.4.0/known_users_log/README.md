# Event Dossier: Zeek known_users.log
### Summary:
- **Description**: Maps Zeek known user observations to OCSF User Inventory Info class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/user_inventory_info
  - https://docs.zeek.org/en/master/logs/known_users.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 5              | Integer    |
| `class_uid`                   | 5003           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | User first seen timestamp                  | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `kuid`                  | Observation unique ID                      |                            |
| `user.name`                   | `user`                  | Username observed                          |                            |
| `duration`                    | `duration`              | Observation duration                       | Convert to milliseconds    |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `observables[].value`         | `host_ip`               | ip          | Host IP address            |
| `observables[].value`         | `remote_ip`             | ip          | Remote IP address          |
| `observables[].value`         | `protocol`              | protocol    | Authentication protocol    |
| `observables[].value`         | `host_vlan`             | vlan        | Host VLAN ID               |
| `observables[].value`         | `host_inner_vlan`       | vlan        | Host inner VLAN ID         |
| `observables[].value`         | `remote_vlan`           | vlan        | Remote VLAN ID             |
| `observables[].value`         | `remote_inner_vlan`     | vlan        | Remote inner VLAN ID       |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `num_conns`              | Number of observed connections                |
| `long_conns`             | Count of long connections                     |
| `annotations`            | Observation annotations                       |
| `last_active_session`    | Last seen session                            |
| `last_active_interval`   | Last seen interval                           |
