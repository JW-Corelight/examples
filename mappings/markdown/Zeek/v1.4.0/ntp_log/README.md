# Event Dossier: Zeek ntp.log
### Summary:
- **Description**: Maps Zeek NTP protocol events to OCSF NTP Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/ntp_activity
  - https://docs.zeek.org/en/master/logs/ntp.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 4              | Integer    |
| `class_uid`                   | 4013           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |

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
| `version`                     | `version`               | NTP protocol version                       | Convert to string          |
| `precision`                   | `precision`             | Clock precision                            | Convert to integer         |
| `delay`                       | `root_delay`            | Round-trip delay                           | Convert to milliseconds    |
| `dispersion`                  | `root_disp`             | Clock dispersion                           | Convert to milliseconds    |
| `stratum_id`                 | `stratum`               | Server stratum level                       | Direct integer mapping     |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `activity_id`         | `mode`           | If 1 → 1 (Symmetric Active)       | NTP mode mapping                          |
| `activity_id`         | `mode`           | If 2 → 2 (Symmetric Passive)      | NTP mode mapping                          |
| `activity_id`         | `mode`           | If 3 → 3 (Client)                 | NTP mode mapping                          |
| `activity_id`         | `mode`           | If 4 → 4 (Server)                 | NTP mode mapping                          |
| `activity_id`         | `mode`           | If 5 → 5 (Broadcast)              | NTP mode mapping                          |
| `activity_id`         | `mode`           | If 6 → 6 (Control)                | NTP mode mapping                          |
| `activity_id`         | `mode`           | If 7 → 7 (Private)                | NTP mode mapping                          |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `poll`                   | Maximum interval between messages            |
| `ref_id`                 | Reference clock identifier                   |
| `ref_time`               | Reference timestamp                          |
| `org_time`               | Originate timestamp                          |
| `rec_time`               | Receive timestamp                            |
| `xmt_time`               | Transmit timestamp                           |
| `num_exts`               | Number of extension fields                   |
