# Event Dossier: Zeek wireguard.log
### Summary:
- **Description**: Maps Zeek WireGuard tunnel events to OCSF Tunnel Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/tunnel_activity
  - https://docs.zeek.org/en/master/logs/wireguard.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 4              | Integer    |
| `class_uid`                   | 4014           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `protocol_name`               | "WireGuard"    |            |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Tunnel detection timestamp                 | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | Server IP address                          | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | Server port                                | Type: port_t               |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `activity_id`         | `established`    | If true → 1 (Open)                | Tunnel established                         |
| `activity_id`         | `established`    | If false → 0 (Unknown)            | Tunnel not established                     |
| `status_id`           | `established`    | If true → 1 (Success)             | Tunnel successfully established            |
| `status_id`           | `established`    | If false → 2 (Failure)            | Tunnel failed to establish                 |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `initiations`            | Number of handshake initiation packets       |
| `responses`              | Number of handshake response packets         |
