# Event Dossier: Zeek wireguard.log

### Summary:
- **Description**: Translates a Zeek wireguard.log to OCSF Tunnel Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/tunnel_activity](https://schema.ocsf.io/1.3.0/classes/tunnel_activity)  
  - [https://docs.zeek.org/en/master/logs/wireguard.html](https://docs.zeek.org/en/master/logs/wireguard.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 4 | Integer |
| class_uid | 4014 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| protocol_name | "WireGuard" |  |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the WireGuard tunnel was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the WireGuard tunnel was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| src_endpoint.pubkey | initiator_pubkey | Public key of the initiating host. | Base64-encoded public key from handshake initiation. Type is String. |
| dst_endpoint.pubkey | responder_pubkey | Public key of the responding host. | Base64-encoded public key from handshake response. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| activity_id | established | Tunnel established flag. | If true then "1" (Open), else "0" (Unknown). Type is Integer. |
| status_id | established | Tunnel established flag. | If true then "1" (Success), else "2" (Failure). Type is Integer. |
| tunnel_stats.packets_in | responses | Number of handshake response packets. | Only if monitoring established tunnel. Type is Integer. |
| tunnel_stats.packets_out | initiations | Number of handshake initiation packets. | Only if monitoring established tunnel. Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | ephemeral_pubkey | Ephemeral public key used for key exchange. | Base64-encoded temporary key for this handshake. Type is String. |
| unmapped | mac1 | First MAC field from handshake. | Used for sender authentication. Type is String. |
| unmapped | mac2 | Second MAC field from handshake. | Used for receiver authentication. Type is String. |