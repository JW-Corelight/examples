# Event Dossier: Zeek notice.log
### Summary:
- **Description**: Translates a Zeek notice.log to OCSF. 

- **Event References**:
  - https://schema.ocsf.io/1.4.0/classes/network_activity
  - https://docs.zeek.org/en/master/logs/notice.html
  - https://docs.zeek.org/en/master/scripts/base/protocols/notice/main.zeek.html#type-Conn::Info

 ### OCSF Version: v1.4.0
  
 ### Static value mapping
| OCSF field                          | Value        | Type       |
| ----------------------------------- | ------------ | ---------- |
| `metadata.version`                  | "1.4.0"      |            |
| `category_uid`                      | 4            | Integer    |
| `class_uid`                         | 4001         | Integer    |
| `metadata.product.name`             | "Zeek"       |            |
| `metadata.product.vendor_name`      | "Zeek"       |            |
| `connection_info.direction_id`      | 0            | Integer    |


 ### Direct field mapping:
| OCSF                          | Raw             | Zeek Field Description                                                                  | Notes                   |
| ----------------------------- | --------------- | --------------------------------------------------------------------------------------- | ----------------------- |
| `time`                        | `ts`            | Time when the connection began.                                                         | Convert to epoch value. <br>Type is timestamp_t (Long). |
| `start_time`                  | `ts`            | Time when the connection began.                                                         | Convert to epoch value. <br>Type is timestamp_t (Long). |
| `metadata.logged_time`        | `_write_ts`     | Timestamp indicating when the log entry was written to disk.                            | Convert to epoch value. <br>Type is timestamp_t (Long). |
| `metadata.loggers[].name`     | `_system_name`  | Name of the system or logging subsystem generating the log entry.                       |                         |
| `metadata.log_name`           | `_path`         | Log name.                                                                               |                         |
| `metadata.uid`                | `uid`           | Unique ID for the connection.                                                           |                         |
| `src_endpoint.ip`             | `id.orig_h`     | The originator’s IP address.                                                            | Type is ip_t.           |
| `src_endpoint.port`           | `id.orig_p`     | The originator’s port number.                                                           | Type is port_t (Integer). |
| `src_endpoint.location.country` | `orig_cc`     | Country code for GeoIP lookup of the originating IP address.                            |                         |
| `src_endpoint.mac`            | `orig_l2_addr`  | Link-layer address of the originator, if available.                                     | Type is mac_t.          |
| `dst_endpoint.ip`             | `id.resp_h`     | The responder’s IP address.                                                             | Type is ip_t.           |
| `dst_endpoint.port`           | `id.resp_p`     | The responder’s port number.                                                            | Type is port_t (Integer). |
| `dst_endpoint.location.country` | `resp_cc`     | Country code for GeoIP lookup of the responding IP address.                             | Type is mac_t.          |
| `dst_endpoint.mac`            | `resp_l2_addr`  | Link-layer address of the responder, if available.                                      |                         |


 ### Conditional mapping:
Fields described here are subject to dynamic mappings contingent on a conditional evaluation of source data.
| OCSF                          | Raw                              | Zeek Field Description                                                       | Evaluation Conditions                                                                                     |
| ----------------------------- | -------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |


 ### Unmapped (proposed):

| OCSF                        | Raw              | Zeek Field Description                                                                  |
| --------------------------- | ---------------- | --------------------------------------------------------------------------------------- |
| ``            | ``   |                                   |
