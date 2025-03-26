# Event Dossier: Zeek suricata_corelight.log

### Summary:
- **Description**: Translates a Zeek suricata_corelight.log to OCSF Detection Finding class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.4.0/classes/detection_finding](https://schema.ocsf.io/1.4.0/classes/detection_finding)  
  - [https://docs.zeek.org/en/master/scripts/packages/community-id/index.html](https://docs.zeek.org/en/master/scripts/packages/community-id/index.html)  
  - [https://corelight.com/blog/suricata-logs-in-zeek](https://corelight.com/blog/suricata-logs-in-zeek)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.4.0" |  |
| category_uid | 2 | Integer |
| class_uid | 2004 | Integer |
| metadata.product.name | "Suricata" |  |
| metadata.product.vendor_name | "Zeek" |  |
| activity_id | 2 | Integer |
| activity_name | "Detection" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the alert was generated. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the alert was generated. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| evidences[].src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| evidences[].src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| evidences[].dst_endpoint.ip | id.resp_h | The responder's IP address. | Type is ip_t. |
| evidences[].dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| finding_info.uid | suri_id | Unique Suricata alert ID. | Used to track this specific alert. Type is String. |
| severity_id | alert.severity | Numeric severity level. | Maps directly to OCSF severity levels. Type is Integer. |
| finding_info.name | alert.signature | Rule signature description. | Description of the triggered rule. Type is String. |
| connection_info.protocol_name | proto | Transport protocol. | Usually "TCP", "UDP", or "ICMP". Type is String. |
| finding_info.rule_id | alert.signature_id | Suricata signature ID. | Unique identifier for the triggered rule. Type is String. |
| finding_info.rule_version | alert.rev | Signature revision. | Version number of the triggered rule. Type is String. |
| finding_info.category | alert.category | Alert classification category. | Type of threat detected. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| metadata.uid | flow_id | Zeek flow identifier. | If community_id is absent, use flow_id. Type is String. |
| metadata.uid | community_id | Community flow ID. | If present, use as primary identifier. Type is String. |
| observables[].value | community_id | Community flow ID. | If present, add as observable with type="network_id". Type is String. |
| message | alert.category | Alert classification category. | Format as "[{alert.category}] {alert.signature}". Type is String. |
| connection_info.direction_id | flow.toserver | Traffic direction. | If 1 then "1" (Ingress), if 0 then "2" (Egress), else "0" (Unknown). Type is Integer. |
| finding_info.labels[] | alert.gid | Generator ID of the rule. | Rules by GID: 1="Suricata", 2="Stream", 3="Detection", else "Custom". Type is Array of String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| observables[].value | id.vlan | VLAN ID. | VLAN tag for the connection. Type is Integer. |
| observables[].value | id.vlan_inner | Inner VLAN. | Inner VLAN tag for Q-in-Q tunneling. Type is Integer. |
| observables[].value | payload_printable | Payload text. | Human-readable portion of packet payload. Type is String. |
| unmapped | icmp_type | ICMP message type. | Type field in ICMP header. Type is Integer. |
| unmapped | icmp_code | ICMP message code. | Code field in ICMP header. Type is Integer. |
| unmapped | pcap_cnt | Packet capture counter. | Counter of the packet in the PCAP file. Type is Integer. |
| unmapped | alert.metadata | Raw Suricata rule metadata. | Contains additional context from rule definition. Type is Array of String. |
| unmapped | alert.action | Action triggered by the alert. | Can be "allowed", "blocked", "dropped", etc. Type is String. |
| unmapped | app_proto | Application layer protocol. | Detected application protocol. Type is String. |
| unmapped | flow.pkts_toserver | Packets from client to server. | Count of packets in client→server direction. Type is Integer. |
| unmapped | flow.pkts_toclient | Packets from server to client. | Count of packets in server→client direction. Type is Integer. |
| unmapped | flow.bytes_toserver | Bytes from client to server. | Count of bytes in client→server direction. Type is Integer. |
| unmapped | flow.bytes_toclient | Bytes from server to client. | Count of bytes in server→client direction. Type is Integer. |
| unmapped | flow.start | Flow start timestamp. | When the network flow began. Type is timestamp_t. |