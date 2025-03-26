# Event Dossier: Zeek socks.log

### Summary:
- **Description**: Translates a Zeek socks.log to OCSF Tunnel Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/tunnel_activity](https://schema.ocsf.io/1.3.0/classes/tunnel_activity)  
  - [https://docs.zeek.org/en/master/logs/socks.html](https://docs.zeek.org/en/master/logs/socks.html)  
  - [https://docs.zeek.org/en/master/scripts/base/protocols/socks/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/socks/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4014 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 1 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the SOCKS connection was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the SOCKS connection was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The client's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The client's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The SOCKS server's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The SOCKS server's port number. | Type is port_t (Integer). |
| protocol_name | version | SOCKS protocol version. | Format as "SOCKSv{n}". Type is String. |
| user.name | user | Username for proxy authentication. | Type is String. May be absent if no authentication used. |
| tunnel_dst.hostname | request.name | Hostname requested by the client. | Type is String. |
| tunnel_dst.ip | request.host | IP address requested by the client. | Type is ip_t. |
| tunnel_dst.port | request_p | Port requested by the client. | Type is port_t (Integer). |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| status_id | status | Connection status. | If "succeeded" then "1" (Success), else "2" (Failure). Type is Integer. |
| tunnel_type | bound.name, bound.host | The proxy destination. | If bound fields are present, "SOCKS_BOUND", else "SOCKS". Type is String. |
| tunnel_dst.hostname | bound.name | Hostname bound by the server. | Only if bound.name is present, otherwise use request.name. Type is String. |
| tunnel_dst.ip | bound.host | IP address bound by the server. | Only if bound.host is present, otherwise use request.host. Type is ip_t. |
| tunnel_dst.port | bound_p | Port bound by the server. | Only if bound_p is present, otherwise use request_p. Type is port_t (Integer). |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | password | Authentication password. | Typically not logged for security reasons unless specifically configured. |
| unmapped | request_host_type | Type of address used in the client request. | Address type code (1=IPv4, 3=hostname, 4=IPv6). |
| unmapped | bound_host_type | Type of address used in the server bind. | Address type code (1=IPv4, 3=hostname, 4=IPv6). |
| unmapped | client_auth_method | Authentication method requested by client. | Authentication method code (0=none, 2=username/password). |
| unmapped | server_auth_method | Authentication method selected by server. | Authentication method code (0=none, 2=username/password). |