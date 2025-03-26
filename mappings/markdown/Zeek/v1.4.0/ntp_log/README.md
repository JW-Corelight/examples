# Event Dossier: Zeek ntp.log

### Summary:
- **Description**: Translates a Zeek ntp.log to OCSF NTP Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/ntp_activity](https://schema.ocsf.io/1.3.0/classes/ntp_activity)  
  - [https://docs.zeek.org/en/master/logs/ntp.html](https://docs.zeek.org/en/master/logs/ntp.html)
  - [https://docs.zeek.org/en/master/scripts/base/protocols/ntp/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/ntp/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4013 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| connection_info.protocol_name | "NTP" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the NTP packet was observed. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the NTP packet was observed. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The client's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The client's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The server's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The server's port number. | Type is port_t (Integer). |
| version | version | NTP protocol version. | Convert to string. Type is String. |
| precision | precision | Clock precision. | Powers of two exponent. Type is Integer. |
| delay | root_delay | Round-trip delay to the reference clock. | Convert to milliseconds. Type is Float. |
| dispersion | root_disp | Maximum error due to clock frequency tolerance. | Convert to milliseconds. Type is Float. |
| stratum_id | stratum | Stratum level of the clock. | 1 is primary reference, >1 is secondary. Type is Integer. |
| poll | poll | Maximum interval between successive messages. | In log2 seconds. Type is Integer. |
| ref_id | ref_id | Reference clock identifier. | For stratum 0, this is a 4-character string. For stratum 1+ this is the source's IP address. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| activity_id | mode | NTP operation mode. | If 1 → 1 (Symmetric Active), if 2 → 2 (Symmetric Passive), if 3 → 3 (Client), if 4 → 4 (Server), if 5 → 5 (Broadcast), if 6 → 6 (Control), if 7 → 7 (Private), else 0 (Unknown). Type is Integer. |
| type_uid | activity_id | Type identifier. | Calculate as (class_uid * 100) + activity_id. Type is Integer. |
| status_id | leap | Leap indicator. | If 0 → 1 (Success), if 1 → 2 (Failure, clock unsynchronized), if 2 → 3 (Suppressed, leap second warning), if 3 → 4 (Failure, alarm condition). Type is Integer. |
| server_info.clock_source | ref_id, stratum | Reference clock source. | For stratum 1, this is the reference ID (e.g., "GPS", "PPS", etc.). For stratum >1, this is the server's IP. Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | ref_time | Reference timestamp. | Time when the system clock was last set or corrected. Type is timestamp_t. |
| unmapped | org_time | Originate timestamp. | Time at the client when the request departed for the server. Type is timestamp_t. |
| unmapped | rec_time | Receive timestamp. | Time at the server when the request arrived from the client. Type is timestamp_t. |
| unmapped | xmt_time | Transmit timestamp. | Time at the server when the response left for the client. Type is timestamp_t. |
| unmapped | num_exts | Number of extension fields. | Count of NTP extension fields present. Type is Integer. |
| unmapped | keyid | Key identifier. | Used for authenticated NTP. Type is Integer. |
| unmapped | leap | Leap indicator. | Warning of an impending leap second to be inserted in the NTP timescale. Type is Integer. |