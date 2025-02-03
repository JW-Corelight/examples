# Event Dossier: Zeek ldap.log
### Summary:
- **Description**: Maps Zeek LDAP authentication events to OCSF Authentication class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/authentication
  - https://docs.zeek.org/en/master/logs/ldap.html
  - https://docs.zeek.org/en/master/scripts/base/protocols/ldap/main.zeek.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 3              | Integer    |
| `class_uid`                   | 3002           | Integer    |
| `auth_protocol_id`            | 99             | Integer    |
| `auth_protocol`               | "LDAP"         |            |
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
| `dst_endpoint.ip`             | `id.resp_h`             | LDAP server IP                             | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | LDAP server port                           | Type: port_t               |
| `connection_info.protocol_name` | `proto`               | Transport protocol                          |                            |
| `message`                     | `diagnostic_message`     | Error or status message                    |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `result`         | If "success" → 1 (Success)        | Authentication succeeded                   |
| `status_id`           | `result`         | If not "success" → 2 (Failure)    | Authentication failed                      |
| `auth_factors`        | `opcode`         | If "bind simple" → [1]            | Password authentication                    |
| `auth_factors`        | `opcode`         | If "bind SASL" → [2]              | Certificate/token authentication           |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `message_id`             | LDAP message identifier                      |
| `version`                | LDAP protocol version                        |
| `object`                 | LDAP object identifier                       |
| `argument`               | Additional arguments                         |
