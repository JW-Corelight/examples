# Event Dossier: Zeek socks.log
### Summary:
- **Description**: Maps Zeek SOCKS proxy events to OCSF Tunnel Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/tunnel_activity
  - https://docs.zeek.org/en/master/logs/socks.html
  - https://docs.zeek.org/en/master/scripts/base/protocols/socks/main.zeek.html

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
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Proxy connection detection time            | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | SOCKS server IP                            | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | SOCKS server port                          | Type: port_t               |
| `protocol_name`               | `version`               | SOCKS protocol version                     | Format as "SOCKSv{n}"      |
| `user.name`                   | `user`                  | Username for proxy authentication          |                            |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `observables[].value`         | `request.host`          | hostname    | Requested destination host |
| `observables[].value`         | `request.name`          | hostname    | Requested hostname         |
| `observables[].value`         | `bound.host`            | hostname    | Bound destination host     |
| `observables[].value`         | `bound.name`            | hostname    | Bound hostname             |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `status`         | If "succeeded" → 1 (Success)      | Proxy connection succeeded                 |
| `status_id`           | `status`         | If not "succeeded" → 2 (Failure)  | Proxy connection failed                    |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `password`               | Authentication password                       |
| `request_p`              | Requested destination port                    |
| `bound_p`                | Server bound port                            |
