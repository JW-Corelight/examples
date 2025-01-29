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
| `connection_info.protocol_num`      | 17           | Integer    |


 ### Direct field mapping:
| OCSF                           | Raw                         | Zeek Field Description                                                                  | Notes                   |
| ------------------------------ | --------------------------- | --------------------------------------------------------------------------------------- | ----------------------- |
| `time`                         | `ts`                        | The earliest time at which a DHCP message over the associated connection is observed.   | Convert to epoch value. <br>Type is Integer. |
| `start_time`                   | `ts`                        | The earliest time at which a DHCP message over the associated connection is observed.   | Convert to epoch value. <br>Type is Integer. |
| `metadata.logged_time`         | `_write_ts`                 | Timestamp indicating when the log entry was written to disk.                            | Convert to epoch value. <br>Type is Integer. |
| `metadata.loggers[].name`      | `_system_name`              | Name of the system or logging subsystem generating the log entry.                       |                         |
| `metadata.log_name`            | `_path`                     | Log name.                                                                               |                         |
| `metadata.uid`                 | `uid`                       | Unique ID for the connection.                                                           |                         |
| `src_endpoint.ip`              | `client_addr`               | IP address of the client. <br>If a transaction is only a client sending INFORM messages then there is no lease information exchanged so this is helpful to know who sent the messages. <br>Getting an address in this field does require that the client sources at least one DHCP message using a non-broadcast address. | |
| `src_endpoint.hostname`        | `host_name`                 | Name given by client in Hostname option 12.                                             |                         |
| `src_endpoint.domain`          | `client_fqdn`               | FQDN given by client in Client FQDN option 81.                                          |                         |
| `src_endpoint.mac`             | `mac`                       | Client's hardware address.                                                              |                         |
| `dst_endpoint.ip`              | `server_addr`               | 	IP address of the server involved in actually handing out the lease. <br>There could be other servers replying with OFFER messages which won't be represented here. <br>Getting an address in this field also requires that the server handing out the lease also sources packets from a non-broadcast IP address. | |
| `dst_endpoint.domain`          | `domain`                    | Domain given by the server in option 15.                                                |                         |
| `duration`                     | `duration`                  | Duration of the DHCP session representing the time from the first message to the last.  | Convert to a milliseconds integer. <br>Type is Integer. |
| `lease_dur`                    | `lease_time`                | IP address lease interval.                                                              | Convert to a seconds integer. <br>Type is Integer. |


 ### Conditional mapping:
Fields described here are subject to dynamic mappings contingent on a conditional evaluation of source data.
| OCSF                           | Raw               | Zeek Field Description                                              | Evaluation Conditions                                                                   |
| ------------------------------ | ----------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `activity_id`                  | `msg_types`       | The DHCP message types seen by this DHCP transaction. <br>Note that Zeek doesn't emit an event when DHCP lease expires, so there is no EXPIRE message type. | If "DISCOVER" then "1", <br>if "OFFER" then "2", <br>if "REQUEST" then "3", <br>if "DECLINE" then "4", <br>if "ACK" then "5", <br>if "NAK" then "6", <br>if "RELEASE" then "7", <br>if "INFORM" then "8", <br>else "0". <br>Type is Integer. |
| `type_uid`                     | `msg_types`       | The DHCP message types seen by this DHCP transaction.               | (`class_uid` * 100) + `activity_id` <br>Type is Integer. |
| `connection_info.protocol_ver_id` | `client_addr`  | IP address of the client.                                           | If `client_addr` is IPv6 format then "6", <br>else "4". <br>Type is Integer. |
| `message`                      | `client_message` and/or `server_message` | `client_message`: "Message typically accompanied with a DHCP_DECLINE so the client can tell the server why it rejected an address." <br>`server_message`: "Message typically accompanied with a DHCP_NAK to let the client know why it rejected the request." | If `client_message` or `server_message` exists, prefix with "Client message:" or "Server message:" respectively, then concatenate into a single value. |
| `uid`                          | `uids`            | A series of unique identifiers of the connections over which DHCP is occurring. This behavior with multiple connections is unique to DHCP because of the way it uses broadcast packets on local networks. | Concatenate `uids` array into a single comma-separated value. |


 ### Unmapped:
| OCSF       | Raw               | Zeek Field Description                                              |
| ---------- | ----------------- | ------------------------------------------------------------------- |
| `unmapped` | `requested_addr`  | IP address requested by the client.                                 |
| `unmapped` | `assigned_addr`   | IP address assigned by the server.                                  |
| `uid(s[])` | `uids`            | A series of unique identifiers of the connections over which DHCP is occurring. This behavior with multiple connections is unique to DHCP because of the way it uses broadcast packets on local networks. |
