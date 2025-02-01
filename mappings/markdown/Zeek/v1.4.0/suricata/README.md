# Event Dossier: Zeek suricata_corelight.log
### Summary:
- **Description**: Maps Suricata alerts via Corelight/Zeke to OCSF Detection Finding
- **Event References**:
  - https://schema.ocsf.io/1.4.0/classes/detection_finding
  - https://docs.zeek.org/en/master/scripts/packages/community-id/index.html
  - https://corelight.com/blog/suricata-logs-in-zeek

### OCSF Version: v1.4.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.4.0"        |            |
| `category_uid`                | 2              | Integer    |
| `class_uid`                   | 2004           | Integer    |
| `metadata.product.name`       | "Suricata"     |            |
| `metadata.product.vendor_name`| "Corelight"    |            |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | Alert timestamp                            | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Record write time                          | Convert to epoch timestamp |
| `metadata.loggers[].name`     | `_system_name`          | Generating system name                     |                            |
| `evidences[].src_endpoint.ip` | `id.orig_h`             | Originator IP                              | Type: ip_t                 |
| `evidences[].src_endpoint.port` | `id.orig_p`           | Originator port                            | Type: port_t               |
| `evidences[].dst_endpoint.ip` | `id.resp_h`             | Responder IP                               | Type: ip_t                 |
| `evidences[].dst_endpoint.port` | `id.resp_p`           | Responder port                             | Type: port_t               |
| `finding_info.uid`            | `suri_id`               | Unique Suricata alert ID                   |                            |
| `severity_id`                 | `alert.severity`        | Numeric severity level                     | Direct 1:1 mapping         |
| `activity_id`                 | `alert.action`          | Action taken (1=Create, 3=Close, etc.)      |                            |
| `finding_info.name`           | `alert.signature`       | Rule signature description                 |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `metadata.uid`        | `flow_id`        | If community_id absent             | Fallback unique identifier                 |
| `observables[].value` | `community_id`   | If present → type="network_id"    | Preferred flow identifier                  |
| `message`             | `alert.category` | Combine with `alert.signature`     | Format: "[Category] Signature: [Message]"  |

### Network Observable Additions:
| OCSF Field                     | Zeek Field              | Type        |
|-------------------------------|-------------------------|-------------|
| `observables[].value`         | `id.vlan`               | VLAN ID      |
| `observables[].value`         | `id.vlan_inner`         | Inner VLAN   |
| `observables[].value`         | `payload_printable`     | Payload text |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `icmp_type`              | ICMP message type                           |
| `icmp_code`              | ICMP message code                            |
| `pcap_cnt`               | Packet capture counter                       |
| `alert.metadata`         | Raw Suricata rule metadata                   |
