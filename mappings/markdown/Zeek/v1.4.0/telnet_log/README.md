# Event Dossier: Zeek telnet.log
### Summary:
- **Description**: Maps Zeek Telnet session events to OCSF Network Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/network_activity
  - https://docs.zeek.org/en/master/logs/telnet.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 4              | Integer    |
| `class_uid`                   | 4001           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Event timestamp                           | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | Server IP address                          | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | Server port                                | Type: port_t               |
| `raw_data`                    | `data`                  | Initial connection bytes                   |                            |

### Environment mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `connection_info.terminal_type` | `terminal_type`         | String      | Terminal type identifier   |
| `connection_info.terminal_speed` | `terminal_speed`       | String      | Terminal speed setting     |
| `connection_info.display`     | `x_display_location`     | String      | X11 display location       |

### Observable mapping:
| OCSF Field                     | Zeek Field                    | Type        | Notes                      |
|-------------------------------|------------------------------|-------------|----------------------------|
| `observables[].value`         | `environ_value_names[]`       | env_var     | Environment variable names  |
| `observables[].value`         | `environ_value_values[]`      | env_var     | Environment variable values |

### TN3270 mapping:
| OCSF Field                     | Zeek Field                    | Type        | Notes                      |
|-------------------------------|------------------------------|-------------|----------------------------|
| `unmapped.tn3270`             | `tn3270`                     | Boolean     | TN3270 session flag        |
| `unmapped.tn3270e`            | `tn3270e`                    | Boolean     | TN3270E session flag       |
| `unmapped.device_type`        | `tn3270e_device_type_request` | String      | Requested device type      |
| `unmapped.device_type_is`     | `tn3270e_device_type_is`     | String      | Actual device type         |
