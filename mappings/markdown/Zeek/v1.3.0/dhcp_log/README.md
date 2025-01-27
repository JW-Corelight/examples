# Event Dossier: Zeek dhcp.log
### Summary:
- **Description**: Translates a Zeek dhcp.log to OCSF. 
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/dhcp_activity
  - https://docs.zeek.org/en/master/logs/dhcp.html
  - https://docs.zeek.org/en/master/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info


 ### OCSF Version: v1.3.0


 ### Static value mapping:
| OCSF field                          | Value        | Type       |
| ----------------------------------- | ------------ | ---------- |
| `metadata.version`                  | "1.3.0"      |            |
| `category_uid`                      | "4"          | Integer    |
| `class_uid`                         | "4004"       | Integer    |
| `severity_id`                       | "1"          | Integer    |
| `metadata.product.name`             | "Zeek"       |            |
| `metadata.product.vendor_name`      | "Zeek"       |            |


 ### Direct field mapping:
| OCSF                           | Raw                         | Zeek Field Description                                                                  | Notes                   |
| ------------------------------ | --------------------------- | --------------------------------------------------------------------------------------- | ----------------------- |
| `time`                         | `ts`                        | Timestamp indicating when the event occurred.                                           | Convert to epoch value. <br>Type is Integer. |
| `start_time`                   | `ts`                        | Timestamp indicating when the event occurred.                                           | Convert to epoch value. <br>Type is Integer. |
| `metadata.logged_time`         | `_write_ts`                 | Timestamp indicating when the log entry was written to disk.                            | Convert to epoch value. <br>Type is Integer. |
| `metadata.loggers[].name`      | `_system_name`              | Name of the system or logging subsystem generating the log entry.                       |                         |
| `metadata.log_name`            | `_path`                     | Log name.                                                                               |                         |
| `metadata.uid`                 | `uid`                       | Unique ID for the connection.                                                           |                         |
| `src_endpoint.ip`              | `id.orig_h`                 | The originator’s IP address.                                                            |                         |
| `src_endpoint.port`            | `id.orig_p`                 | The originator’s port number.                                                           | Integer                 |
| `dst_endpoint.ip`              | `id.resp_h`                 | The responder’s IP address.                                                             |                         |
| `dst_endpoint.port`            | `id.resp_p`                 | The responder’s port number.                                                            | Integer                 |


 ### Conditional mapping:
Fields described here are subject to dynamic mappings contingent on a conditional evaluation of source data.
| OCSF                           | Raw               | Zeek Field Description                                              | Evaluation Conditions                                                                   |
| ------------------------------ | ----------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `activity_id`                  | `auth_success`    | Authentication result.                                              | If "true" then "99", <br>if "false" then "4", <br>else "6". <br>Type is Integer.        |
| `activity_name`                | `auth_success`    | Authentication result.                                              | If "true" then "Authorization Successful", <br>else defined by activity_id.             |
| `type_uid`                     | `auth_success`    | Authentication result.                                              | If "true" then "400799", <br>if "false" then "400704", <br>else "400706". <br>Type is Integer. |


 ### Unmapped:
| OCSF       | Raw               | Zeek Field Description                                              |
| ---------- | ----------------- | ------------------------------------------------------------------- |
| `unmapped` | ``    |                                        |
