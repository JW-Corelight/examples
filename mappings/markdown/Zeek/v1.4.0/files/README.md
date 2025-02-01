# Event Dossier: Zeek files.log
### Summary:
- **Description**: Maps Zeek file transfer events to OCSF Data Security Finding class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/data_security_finding
  - https://docs.zeek.org/en/master/logs/files.html
  - https://corelight.blog/zeek-file-analysis

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 2              | Integer    |
| `class_uid`                   | 2006           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `time`                        | `ts`                    | File first seen timestamp                  | Convert to epoch timestamp |
| `metadata.logged_time`        | `_write_ts`             | Log write time                             | Convert to epoch timestamp |
| `file.uid`                    | `fuid`                  | Unique file identifier                     |                            |
| `file.name`                   | `filename`              | Original filename from source             |                            |
| `file.mime_type`              | `mime_type`             | Detected file type                         |                            |
| `file.size`                   | `total_bytes`           | Complete file size                         |                            |
| `file.hashes[].value`         | `md5`                   | MD5 digest                                 | `algorithm_id: 1`          |
| `file.hashes[].value`         | `sha1`                  | SHA1 digest                               | `algorithm_id: 3`          |
| `file.hashes[].value`         | `sha256`                | SHA256 digest                             | `algorithm_id: 4`          |
| `src_endpoint.ip`             | `id.orig_h`             | Originator IP                              | Type: ip_t                 |
| `src_endpoint.port`           | `id.orig_p`             | Originator port                            | Type: port_t               |
| `dst_endpoint.ip`             | `id.resp_h`             | Responder IP                               | Type: ip_t                 |
| `dst_endpoint.port`           | `id.resp_p`             | Responder port                             | Type: port_t               |
| `connection_info.protocol_name` | `source`              | File transfer protocol                     |                            |

### Conditional mapping:
| OCSF Field             | Zeek Field       | Condition                          | Notes                                      |
|-----------------------|------------------|------------------------------------|--------------------------------------------|
| `file_result.path`    | `extracted`      | If file extraction occurred        |                                            |
| `status_id`           | `timedout`       | true → 3 (Suppressed)              | Analysis timeout as suppression indicator  |
| `status_id`           | `timedout`       | false → 1 (New)                    | Default status for active findings         |
| `observables[].value` | `conn_uids`      | If multiple connections present    | Type: "connection_id"                      |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `depth`                  | File nesting depth in transfer               |
| `analyzers`              | File analysis types performed                |
| `local_orig`             | Network locality flag                        |
| `is_orig`                | File transfer direction flag                 |
