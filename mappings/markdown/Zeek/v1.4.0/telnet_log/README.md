# Event Dossier: Zeek telnet.log

### Summary:
- **Description**: Translates a Zeek telnet.log to OCSF Network Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/network_activity](https://schema.ocsf.io/1.3.0/classes/network_activity)  
  - [https://docs.zeek.org/en/master/logs/telnet.html](https://docs.zeek.org/en/master/logs/telnet.html)
  - [https://docs.zeek.org/en/master/scripts/base/protocols/login/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/login/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4001 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 6 | Integer |
| activity_name | "Traffic" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the Telnet session was initiated. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the Telnet session was initiated. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The client's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The client's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The server's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The server's port number. | Type is port_t (Integer). |
| raw_data | data | Initial connection bytes. | First bytes of the connection. Type is String. |
| connection_info.terminal_type | terminal_type | Terminal type identifier. | Terminal type reported by client. Type is String. |
| connection_info.terminal_speed | terminal_speed | Terminal speed setting. | Terminal speed reported by client. Type is String. |
| connection_info.display | x_display_location | X11 display location. | X Window display location for X11 forwarding. Type is String. |
| app_name | _path | Application protocol name. | Fixed value "telnet". Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| type_uid | activity_id | Type identifier. | Calculate as (class_uid * 100) + activity_id = 400106. Type is Integer. |
| user.name | login_success | Username from successful login. | If login_success is true, extract username from login information. Type is String. |
| status_id | login_success | Authentication status. | If login_success is true, "1" (Success), if false, "2" (Failure), else "0" (Unknown). Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | environ_vars | Environmental variables sent during the connection setup. | Type is Array of String. |
| unmapped | environ_values | Values of the environmental variables. | Type is Array of String. |
| unmapped | login_success | Whether the login was successful. | Type is Boolean. |
| unmapped | password | Password if captured. | May be obscured for security. Type is String. |
| unmapped | client_version | Client version identifier. | Type is String. |
| unmapped | server_version | Server version identifier. | Type is String. |
| unmapped | tn3270 | TN3270 session flag. | Whether this is a TN3270 terminal session. Type is Boolean. |
| unmapped | tn3270e | TN3270E session flag. | Whether this is a TN3270E terminal session. Type is Boolean. |
| unmapped | tn3270e_device_type_request | Requested device type. | For TN3270E sessions. Type is String. |
| unmapped | tn3270e_device_type_is | Actual device type. | For TN3270E sessions. Type is String. |