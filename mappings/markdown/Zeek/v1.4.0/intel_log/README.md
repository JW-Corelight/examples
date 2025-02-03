# Event Dossier: Zeek intel.log
### Summary:
- **Description**: Maps Zeek intelligence framework matches to OCSF Detection Finding class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/detection_finding
  - https://docs.zeek.org/en/master/frameworks/intel.html
  - https://docs.zeek.org/en/master/scripts/base/frameworks/intel/main.zeek.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 2              | Integer    |
| `class_uid`                   | 2004           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 3              | Integer    |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Intelligence match timestamp               | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `evidences[].src_endpoint.ip` | `id.orig_h`             | Originator IP address                      | Type: ip_t                 |
| `evidences[].src_endpoint.port` | `id.orig_p`           | Originator port                            | Type: port_t               |
| `evidences[].dst_endpoint.ip` | `id.resp_h`             | Responder IP address                       | Type: ip_t                 |
| `evidences[].dst_endpoint.port` | `id.resp_p`           | Responder port                             | Type: port_t               |
| `finding_info.data_sources[]` | `sources`               | Intelligence sources                        | Array of strings           |

### Observable mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `observables[].value`         | `seen.indicator`        | String      | Matched indicator value    |
| `observables[].type`          | `seen.indicator_type`   | String      | Indicator type             |
| `observables[].location`      | `seen.where`            | String      | Where indicator was seen   |

### File Evidence mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `evidences[].file.uid`        | `fuid`                  | String      | File unique ID             |
| `evidences[].file.mime_type`  | `file_mime_type`        | String      | File MIME type             |
| `evidences[].file.desc`       | `file_desc`             | String      | File description           |
