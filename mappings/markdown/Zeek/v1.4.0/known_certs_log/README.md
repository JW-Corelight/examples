# Event Dossier: Zeek known_certs.log

### Summary:
- **Description**: Translates a Zeek known_certs.log to OCSF Device Inventory Info class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/device_inventory_info](https://schema.ocsf.io/1.3.0/classes/device_inventory_info)  
  - [https://docs.zeek.org/en/master/logs/known_certs.html](https://docs.zeek.org/en/master/logs/known_certs.html)

### Static value mapping:

| OCSF field | Value | Type |
| :---- | :---- | :---- |
| metadata.version | "1.3.0" |  |
| category_uid | 5 | Integer |
| class_uid | 5001 | Integer |
| metadata.product.name | "Zeek" |  |
| metadata.product.vendor_name | "Zeek" |  |
| severity_id | 1 | Integer |
| activity_id | 2 | Integer |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the certificate was first observed. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the certificate was first observed. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | kuid | Observation unique ID. | Similar to uid, but specific to known entity tracking. Type is String. |
| device.ip | host_ip | Host IP address providing the certificate. | Type is ip_t. |
| device.port | port_num | Server listening port. | Type is port_t (Integer). |
| duration | duration | Observation duration. | How long this certificate has been tracked. Convert to milliseconds. Type is Integer. |
| device.name | subject | Certificate subject name. | May be used for device identification. Type is String. |
| device.certificates[].hash | hash | Certificate hash (fingerprint). | SHA1 hash of the certificate. Type is String. |
| device.certificates[].serial | serial | Certificate serial number. | Type is String. |
| device.certificates[].subject | subject | Certificate subject. | Distinguished Name format. Type is String. |
| device.certificates[].issuer | issuer_subject | Certificate issuer. | Distinguished Name format. Type is String. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| device.certificates[].algorithm_id | cert_key_alg | Certificate key algorithm. | Map algorithm to ID: "rsaEncryption" → 1, "dsaEncryption" → 2, etc. Only if cert_key_alg is present. Type is Integer. |
| device.certificates[].key_size | cert_key_length | Certificate key length in bits. | Only if cert_key_length is present. Type is Integer. |
| device.certificates[].fingerprints[].algorithm_id | hash | Implicit algorithm for hash. | Always set to 3 (SHA1) if hash is present. Type is Integer. |
| device.certificates[].fingerprints[].value | hash | Certificate fingerprint. | Copy of hash value for consistency with certificate schema. Type is String. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| observables[].value | host_vlan | Host VLAN ID. | VLAN tag if present. Type is Integer. |
| observables[].value | host_inner_vlan | Host inner VLAN ID. | Inner VLAN tag for Q-in-Q configurations. Type is Integer. |
| unmapped | last_seen | When certificate was last observed. | Timestamp of most recent sighting. Type is timestamp_t. |
| unmapped | cert_key_alg | Algorithm used for certificate key. | String representation of key algorithm (e.g., "rsaEncryption"). |
| unmapped | cert_key_type | Type of key (e.g., "rsa"). | String representation of key type. |
| unmapped | cert_key_length | Length of certificate key in bits. | Integer representing key strength. |
| unmapped | cert_exponent | Exponent value for RSA keys. | Only present for RSA certificates. |
| unmapped | cert_curve | Curve name for ECC keys. | Only present for elliptic curve certificates. |