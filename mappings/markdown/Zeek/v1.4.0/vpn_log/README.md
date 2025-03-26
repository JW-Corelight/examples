# Event Dossier: Zeek vpn.log

### Summary:
- **Description**: Translates a Zeek vpn.log to OCSF Tunnel Activity class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/tunnel_activity](https://schema.ocsf.io/1.3.0/classes/tunnel_activity)  
  - [https://docs.zeek.org/en/master/logs/vpn.html](https://docs.zeek.org/en/master/logs/vpn.html)
  - [https://github.com/corelight/zeek-community-id](https://github.com/corelight/zeek-community-id)

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
| activity_name | "Open" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the VPN connection was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the VPN connection was detected. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The client's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The client's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The server's IP address. | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The server's port number. | Type is port_t (Integer). |
| protocol_name | proto | Transport protocol. | Usually "tcp" or "udp". Type is String. |
| tunnel_type | vpn_type | VPN protocol type. | Strip "VPNInsights::" prefix. Examples include "IPSEC", "OpenVPN", "WireGuard", "L2TP". Type is String. |
| duration | duration | Connection duration. | How long the tunnel has been active. Convert to milliseconds. Type is Integer. |
| traffic.bytes_in | resp_bytes | Bytes sent from server to client. | Type is Integer. |
| traffic.bytes_out | orig_bytes | Bytes sent from client to server. | Type is Integer. |
| tls.server_name | server_name | Server hostname in TLS connection. | Only for TLS-based VPNs. Type is String. |
| tls.subject | subject | Certificate subject in TLS connection. | Only for TLS-based VPNs. Type is String. |
| tls.issuer | issuer | Certificate issuer in TLS connection. | Only for TLS-based VPNs. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| type_uid | activity_id | Type identifier. | Calculate as (class_uid * 100) + activity_id = 401401. Type is Integer. |
| status_id | duration | Session status. | If duration > 0, "1" (Success), else "0" (Unknown). Type is Integer. |
| traffic.bytes | orig_bytes, resp_bytes | Total bytes transferred. | Sum of orig_bytes and resp_bytes. Type is Integer. |
| tls.ja3_hash.value | ja3 | Client TLS fingerprint. | Only for TLS-based VPNs. Type is String. |
| tls.ja3_hash.algorithm_id | ja3 | Hash algorithm for JA3. | If ja3 exists, set to 1 (MD5). Type is Integer. |
| tls.ja3s_hash.value | ja3s | Server TLS fingerprint. | Only for TLS-based VPNs. Type is String. |
| tls.ja3s_hash.algorithm_id | ja3s | Hash algorithm for JA3S. | If ja3s exists, set to 1 (MD5). Type is Integer. |
| src_endpoint.location.country | orig_cc | Origin country code. | From GeoIP lookup. Type is String. |
| src_endpoint.location.region | orig_region | Origin region. | From GeoIP lookup. Type is String. |
| src_endpoint.location.city | orig_city | Origin city. | From GeoIP lookup. Type is String. |
| dst_endpoint.location.country | resp_cc | Response country code. | From GeoIP lookup. Type is String. |
| dst_endpoint.location.region | resp_region | Response region. | From GeoIP lookup. Type is String. |
| dst_endpoint.location.city | resp_city | Response city. | From GeoIP lookup. Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | community_id | Network flow community ID hash. | Type is String. |
| unmapped | vpn_port | Destination port of the actual VPN service. | May differ from dst_endpoint.port when using a control connection. Type is port_t (Integer). |
| unmapped | stage | Stage of the VPN connection. | Examples include "handshake", "established", "data". Type is String. |
| unmapped | authentication_method | Authentication method used. | Examples include "certificate", "psk", "password". Type is String. |
| unmapped | cipher_suite | Encryption cipher suite. | Cryptographic algorithms used. Type is String. |
| unmapped | key_exchange | Key exchange algorithm. | For example, "DH", "ECDH". Type is String. |
| unmapped | ja3_string | Raw values used to generate the JA3 hash. | Type is String. |
| unmapped | ja3s_string | Raw values used to generate the JA3S hash. | Type is String. |