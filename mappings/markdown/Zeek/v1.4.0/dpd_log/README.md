# Event Dossier: Zeek dpd.log
### Summary:
- **Description**: Maps Zeek Dynamic Protocol Detection (DPD) failures to OCSF Detection Finding class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/detection_finding
  - https://docs.zeek.org/en/master/logs/dpd.html
  - https://docs.zeek.org/en/master/scripts/base/frameworks/dpd/main.zeek

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 2              | Integer    |
| `class_uid`                   | 2004           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 2              | Integer    |
| `activity_id`                 | 1              | Integer    |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Protocol analysis failure timestamp        | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `metadata.uid`                | `uid`                   | Connection unique ID                       |                            |
| `evidences[].src_endpoint.ip` | `id.orig_h`             | Originator IP                              | Type: ip_t                 |
| `evidences[].src_endpoint.port` | `id.orig_p`           | Originator port                            | Type: port_t               |
| `evidences[].dst_endpoint.ip` | `id.resp_h`             | Responder IP                               | Type: ip_t                 |
| `evidences[].dst_endpoint.port` | `id.resp_p`           | Responder port                             | Type: port_t               |
| `finding_info.title`          | `analyzer`              | Protocol analyzer name                      |                            |
| `message`                     | `failure_reason`        | Analysis failure description               |                            |
| `connection_info.protocol_name` | `proto`               | Transport protocol                          |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `observables[].value` | `packet_segment` | If present → type="packet_data"   | Optional packet payload data               |
