# Event Dossier: Zeek kerberos.log
### Summary:
- **Description**: Maps Zeek Kerberos authentication events to OCSF Authentication class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/authentication
  - https://docs.zeek.org/en/master/logs/kerberos.html
  - https://docs.zeek.org/en/master/scripts/base/protocols/krb/main.zeek.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 3              | Integer    |
| `class_uid`                   | 3002           | Integer    |
| `auth_protocol_id`            | 2              | Integer    |
| `auth_protocol`               | "Kerberos"     |            |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Authentication timestamp                   | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `src_endpoint.ip`             | `id.orig_h`             | Client IP address                          | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Client port                                | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | KDC IP address                             | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | KDC port                                   | Type: port_t               |
| `user.name`                   | `client`                | Kerberos client principal                  |                            |
| `service.name`                | `service`               | Requested service name                      |                            |
| `certificate.subject`         | `client_cert_subject`   | Client certificate subject                 |                            |
| `certificate.uid`             | `client_cert_fuid`      | Client certificate file ID                 |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `activity_id`         | `request_type`   | If "AS" → 3 (Auth Ticket)         | Authentication ticket request              |
| `activity_id`         | `request_type`   | If "TGS" → 4 (Service Ticket)     | Service ticket request                     |
| `status_id`           | `success`        | If true → 1 (Success)             | Authentication succeeded                   |
| `status_id`           | `success`        | If false → 2 (Failure)            | Authentication failed                      |
| `status_detail`       | `error_msg`      | If present → error message        | Only present on failure                    |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `from`                   | Ticket valid from time                       |
| `till`                   | Ticket expiration time                       |
| `cipher`                 | Encryption type used                         |
| `forwardable`            | Ticket forwardable flag                      |
| `renewable`              | Ticket renewable flag                        |
