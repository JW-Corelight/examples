# Event Dossier: Zeek ldap_search.log
### Summary:
- **Description**: Maps Zeek LDAP search events to OCSF Authentication class
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
| `activity_id`                 | 6              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Search timestamp                          | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | LDAP server IP                             | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | LDAP server port                           | Type: port_t               |
| `connection_info.protocol_name` | `proto`               | Transport protocol                          |                            |
| `message`                     | `diagnostic_message`     | Error or status message                    |                            |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `observables[].value`         | `base_object`           | dn          | LDAP search base DN        |
| `observables[].value`         | `filter`                | filter      | LDAP search filter         |
| `observables[].value`         | `attributes[]`          | attributes  | Requested attributes       |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `result`         | If "success" → 1 (Success)        | Search succeeded                          |
| `status_id`           | `result`         | If not "success" → 2 (Failure)    | Search failed                             |
| `status_detail`       | `result_count`   | Include count in status detail    | Number of results returned                |
