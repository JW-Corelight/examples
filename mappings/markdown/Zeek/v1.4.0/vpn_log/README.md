# Event Dossier: Zeek vpn.log
### Summary:
- **Description**: Maps Zeek VPN detection events to OCSF Tunnel Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/tunnel_activity
  - https://docs.zeek.org/en/master/logs/vpn.html

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
| `time`                        | `ts`                    | VPN detection timestamp                    | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | Server IP address                          | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | Server port                                | Type: port_t               |
| `protocol_name`               | `proto`                 | Transport protocol                         |                            |
| `tunnel_type`                 | `vpn_type`              | VPN protocol type                          | Strip "VPNInsights::"      |
| `duration`                    | `duration`              | Connection duration                        | Convert to milliseconds    |

### Traffic mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `traffic.bytes_in`            | `orig_bytes`            | Integer     | Bytes from client          |
| `traffic.bytes_out`           | `resp_bytes`            | Integer     | Bytes from server          |

### TLS mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `tls.server_name`             | `server_name`           | String      | Server hostname            |
| `tls.subject`                 | `subject`               | String      | Certificate subject        |
| `tls.issuer`                  | `issuer`                | String      | Certificate issuer         |
| `tls.ja3`                     | `ja3`                   | String      | Client fingerprint         |
| `tls.ja3s`                    | `ja3s`                  | String      | Server fingerprint         |

### Location mapping:
| OCSF Field                          | Zeek Field              | Notes                      |
|-----------------------------------|-------------------------|----------------------------|
| `src_endpoint.location.country`    | `orig_cc`               | Origin country code        |
| `src_endpoint.location.region`     | `orig_region`           | Origin region              |
| `src_endpoint.location.city`       | `orig_city`             | Origin city                |
| `dst_endpoint.location.country`    | `resp_cc`               | Response country code      |
| `dst_endpoint.location.region`     | `resp_region`           | Response region            |
| `dst_endpoint.location.city`       | `resp_city`             | Response city              |
