# Event Dossier: Zeek ntlm.log
### Summary:
- **Description**: Maps Zeek NTLM authentication events to OCSF Authentication class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/authentication
  - https://docs.zeek.org/en/master/logs/ntlm.html
  - https://docs.zeek.org/en/master/scripts/base/protocols/ntlm/main.zeek.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 3              | Integer    |
| `class_uid`                   | 3002           | Integer    |
| `auth_protocol_id`            | 1              | Integer    |
| `auth_protocol`               | "NTLM"         |            |
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
| `dst_endpoint.ip`             | `id.resp_h`             | Server IP address                          | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | Server port                                | Type: port_t               |
| `user.name`                   | `username`              | Authentication username                     |                            |
| `user.domain`                 | `domainname`            | Authentication domain                       |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `success`        | If true → 1 (Success)             | Authentication succeeded                   |
| `status_id`           | `success`        | If false → 2 (Failure)            | Authentication failed                      |
| `status_id`           | `success`        | If absent → 0 (Unknown)           | Status unknown                            |

### Server Details mapping:
| OCSF Field                     | Zeek Field                 | Type        |
|-------------------------------|----------------------------|-------------|
| `dst_endpoint.hostname`        | `server_nb_computer_name`  | String      |
| `dst_endpoint.fqdn`           | `server_dns_computer_name` | String      |
| `observables[].value`         | `server_tree_name`         | String      |
| `src_endpoint.hostname`       | `hostname`                 | String      |
