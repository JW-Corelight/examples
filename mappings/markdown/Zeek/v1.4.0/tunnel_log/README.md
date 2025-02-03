# Event Dossier: Zeek tunnel.log
### Summary:
- **Description**: Maps Zeek tunnel detection events to OCSF Tunnel Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/tunnel_activity
  - https://docs.zeek.org/en/master/logs/tunnel.html
  - https://docs.zeek.org/en/master/scripts/base/frameworks/tunnels/main.zeek.html

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

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Tunnel activity timestamp                  | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Originator IP address                      | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Originator port                            | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | Responder IP address                       | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | Responder port                             | Type: port_t               |
| `protocol_name`               | `tunnel_type`           | Type of tunnel protocol                    | Strip "Tunnel::" prefix    |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `activity_id`         | `action`         | If "DISCOVER" → 1 (Open)          | Tunnel discovery/establishment             |
| `activity_id`         | `action`         | If "EXPIRE" → 2 (Close)           | Tunnel termination                         |
| `activity_id`         | `action`         | If other → 0 (Unknown)            | Unknown tunnel activity                    |
