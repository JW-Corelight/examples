# Event Dossier: Zeek log4shell.log
### Summary:
- **Description**: Maps Zeek Log4Shell vulnerability detection events to OCSF Detection Finding class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/detection_finding
  - https://docs.zeek.org/en/master/logs/log4shell.html
  - https://github.com/corelight/CVE-2021-44228

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 2              | Integer    |
| `class_uid`                   | 2004           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 4              | Integer    |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Detection timestamp                        | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `finding_info.title`          | `name`                  | HTTP header field name                     |                            |
| `message`                     | `value`                 | HTTP header field value                    |                            |
| `http_request.url`            | `http_uri`              | HTTP request URI                           |                            |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type                | Notes                      |
|-------------------------------|-------------------------|---------------------|----------------------------|
| `observables[].value`         | `target_host`           | hostname            | JNDI target host           |
| `observables[].value`         | `target_port`           | port                | JNDI target port           |
| `observables[].value`         | `uri`                   | uri                 | Complete JNDI URI          |
| `observables[].value`         | `stem`                  | hostname            | Base JNDI hostname         |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `status_id`           | `matched_value`  | If true → 2 (In Progress)          | Confirmed Log4Shell attempt                |
| `status_id`           | `matched_value`  | If false → 1 (New)                 | Potential Log4Shell attempt                |
