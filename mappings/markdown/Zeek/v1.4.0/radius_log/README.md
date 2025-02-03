# Event Dossier: Zeek radius.log
### Summary:
- **Description**: Maps Zeek RADIUS authentication events to OCSF Authentication class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/authentication
  - https://docs.zeek.org/en/master/logs/radius.html
  - https://docs.zeek.org/en/master/scripts/base/protocols/radius/main.zeek.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 3              | Integer    |
| `class_uid`                   | 3002           | Integer    |
| `auth_protocol_id`            | 10             | Integer    |
| `auth_protocol`               | "RADIUS"       |            |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Authentication timestamp                   | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | RADIUS server IP                           | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | RADIUS server port                         | Type: port_t               |
| `user.name`                   | `username`              | Authentication username                     |                            |
| `message`                     | `reply_msg`             | Server reply message                        |                            |
| `duration`                    | `ttl`                   | Authentication duration                     | Convert to milliseconds    |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `result`         | If "success" → 1 (Success)        | Authentication succeeded                   |
| `status_id`           | `result`         | If "failed" → 2 (Failure)         | Authentication failed                      |
| `status_id`           | `result`         | If absent → 0 (Unknown)           | Status unknown                            |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `observables[].value`         | `mac`                   | mac_addr    | Client MAC address         |
| `observables[].value`         | `framed_addr`          | ip          | Assigned IP address        |
| `observables[].value`         | `tunnel_client`        | hostname    | Tunnel client endpoint     |
