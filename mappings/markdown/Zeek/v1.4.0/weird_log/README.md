# Event Dossier: Zeek weird.log
### Summary:
- **Description**: Maps Zeek protocol anomaly events to OCSF Detection Finding class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/detection_finding
  - https://docs.zeek.org/en/master/logs/weird-and-notice.html
  - https://docs.zeek.org/en/master/scripts/base/frameworks/notice/weird.zeek

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 2              | Integer    |
| `class_uid`                   | 2004           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Weird occurrence timestamp                 | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `evidences[].src_endpoint.ip` | `id.orig_h`             | Originator IP                              | Type: ip_t                 |
| `evidences[].src_endpoint.port` | `id.orig_p`           | Originator port                            | Type: port_t               |
| `evidences[].dst_endpoint.ip` | `id.resp_h`             | Responder IP                               | Type: ip_t                 |
| `evidences[].dst_endpoint.port` | `id.resp_p`           | Responder port                             | Type: port_t               |
| `finding_info.title`          | `name`                  | Weird type name                            |                            |
| `finding_info.data_sources[]` | `source`                | Protocol analyzer name                      |                            |
| `message`                     | `addl`                  | Additional context                          |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `notice`         | If true → 2 (In Progress)          | Elevated to notice status                  |
| `status_id`           | `notice`         | If false → 1 (New)                 | Default status for new weirds              |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `peer`                   | Zeek cluster node identifier                 |
