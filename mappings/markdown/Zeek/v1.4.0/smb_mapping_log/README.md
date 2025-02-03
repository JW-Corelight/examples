# Event Dossier: Zeek smb_mapping.log
### Summary:
- **Description**: Maps Zeek SMB share mapping events to OCSF SMB Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/smb_activity
  - https://docs.zeek.org/en/master/logs/smb_mapping.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 4              | Integer    |
| `class_uid`                   | 4006           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `activity_id`                 | 99             | Integer    |
| `activity_name`               | "Share Map"     |            |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Share mapping timestamp                    | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | Server IP address                          | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | Server port                                | Type: port_t               |
| `share`                       | `path`                  | Share path                                 | Extract share name         |
| `share_type`                  | `share_type`            | Share type                                 |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `share_type_id`       | `share_type`     | If "DISK" → 1                     | Maps to File                               |
| `share_type_id`       | `share_type`     | If "PIPE" → 2                     | Maps to Pipe                               |
| `share_type_id`       | `share_type`     | If "PRINTER" → 3                  | Maps to Print                              |
| `share_type_id`       | `share_type`     | If other → 99                     | Maps to Other                              |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `native_file_system`     | File system of the share                     |
| `service`                | Type of resource                             |
