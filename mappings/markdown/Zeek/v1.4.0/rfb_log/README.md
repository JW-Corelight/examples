# Event Dossier: Zeek rfb.log
### Summary:
- **Description**: Maps Zeek RFB (Remote Framebuffer/VNC) events to OCSF Network Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/network_activity
  - https://docs.zeek.org/en/master/logs/rfb.html

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
| `app_name`                    | `desktop_name`          | Shared desktop name                        |                            |

### Version mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `connection_info.client_version` | `client_major_version`, `client_minor_version` | String | Format as "x.x" |
| `connection_info.server_version` | `server_major_version`, `server_minor_version` | String | Format as "x.x" |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `auth`           | If true → 1 (Success)             | Authentication successful                  |
| `status_id`           | `auth`           | If false → 2 (Failure)            | Authentication failed                      |
| `status_id`           | `auth`           | If absent → 0 (Unknown)           | Authentication not attempted               |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `authentication_method`   | RFB authentication method used               |
| `share_flag`             | Exclusive or shared session flag             |
| `width`                  | Screen width                                 |
| `height`                 | Screen height                                |
