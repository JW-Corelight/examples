# Event Dossier: Zeek dce_rpc.log
### Summary:
- **Description**: Maps Zeek DCE/RPC protocol events to OCSF SMB Activity class
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/smb_activity
  - https://docs.zeek.org/en/master/logs/dce_rpc.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 4              | Integer    |
| `class_uid`                   | 4006           | Integer    |
| `metadata.product.name`       | "Zeek"         |            |
| `metadata.product.vendor_name`| "Corelight"    |            |
| `severity_id`                 | 1              | Integer    |
| `activity_id`                 | 99             | Integer    |

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
| `share`                       | `named_pipe`            | Named pipe path                            | Strip "\\PIPE\\" prefix    |

### DCE/RPC mapping:
| OCSF Field                     | Zeek Field              | Type        | Notes                      |
|-------------------------------|-------------------------|-------------|----------------------------|
| `dce_rpc.endpoint`            | `endpoint`              | String      | Service endpoint name      |
| `dce_rpc.operation`           | `operation`             | String      | RPC operation name         |
| `dce_rpc.rtt`                 | `rtt`                   | Double      | Round trip time in seconds |
