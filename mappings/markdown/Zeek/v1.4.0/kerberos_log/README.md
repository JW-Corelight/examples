# Event Dossier: Zeek kerberos.log

### Summary:
- **Description**: Translates a Zeek kerberos.log to OCSF Authentication class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/authentication](https://schema.ocsf.io/1.3.0/classes/authentication)  
  - [https://docs.zeek.org/en/master/logs/kerberos.html](https://docs.zeek.org/en/master/logs/kerberos.html)  
  - [https://docs.zeek.org/en/master/scripts/base/protocols/krb/main.zeek.html](https://docs.zeek.org/en/master/scripts/base/protocols/krb/main.zeek.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 3 | Integer |
| class_uid | 3002 | Integer |
| auth_protocol_id | 2 | Integer |
| auth_protocol | "Kerberos" |  |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the authentication occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the authentication occurred. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | uid | Unique ID for the connection. |  |
| src_endpoint.ip | id.orig_h | The originator's IP address. | Type is ip_t. |
| src_endpoint.port | id.orig_p | The originator's port number. | Type is port_t (Integer). |
| dst_endpoint.ip | id.resp_h | The responder's IP address (KDC). | Type is ip_t. |
| dst_endpoint.port | id.resp_p | The responder's port number. | Type is port_t (Integer). |
| user.name | client | Kerberos client principal. | Format: username/realm@DOMAIN |
| service.name | service | Requested service name. | Format: service/host@DOMAIN |
| certificate.subject | client_cert_subject | Client certificate subject. | Only present if client authentication uses X.509. |
| certificate.uid | client_cert_fuid | Client certificate file ID. | Reference to the file.log entry if client authentication uses X.509. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| activity_id | request_type | Kerberos request type. | If "AS" then "3" (Auth Ticket), if "TGS" then "4" (Service Ticket), else "1" (Login). Type is Integer. |
| status_id | success | Authentication success status. | If true then "1" (Success), if false then "2" (Failure), else "0" (Unknown). Type is Integer. |
| status_detail | error_msg | Error message. | If present, use as status detail. Only present on authentication failure. Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| unmapped | from | Ticket valid from time. | Timestamp when the ticket becomes valid. |
| unmapped | till | Ticket expiration time. | Timestamp when the ticket expires. |
| unmapped | cipher | Encryption type used. | Numerical identifier for the encryption algorithm. |
| unmapped | forwardable | Ticket forwardable flag. | Boolean indicating if the ticket can be forwarded. |
| unmapped | renewable | Ticket renewable flag. | Boolean indicating if the ticket can be renewed. |
| unmapped | auth_ticket | Hash of the auth ticket if one was granted. | Only for AS responses. |
| unmapped | ciphertext | The Kerberos encrypted ciphertext. | May be extracted for offline analysis. |