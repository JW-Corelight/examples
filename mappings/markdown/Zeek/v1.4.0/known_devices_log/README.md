# Event Dossier: Zeek known_devices.log

### Summary:
- **Description**: Translates a Zeek known_devices.log to OCSF Device Inventory Info class.  
- **Event References**:  
  - [https://schema.ocsf.io/1.3.0/classes/device_inventory_info](https://schema.ocsf.io/1.3.0/classes/device_inventory_info)  
  - [https://docs.zeek.org/en/master/logs/known_devices.html](https://docs.zeek.org/en/master/logs/known_devices.html)

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
| activity_name | "Device Observed" | Type is String. |

### Direct field mapping:

| OCSF | Raw | Zeek Field Description | Notes |
| :---- | :---- | :---- | :---- |
| time | ts | Timestamp when the device was first observed. | Convert to epoch value. Type is timestamp_t (Long). |
| start_time | ts | Timestamp when the device was first observed. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.logged_time | _write_ts | Timestamp indicating when the log entry was written to disk. | Convert to epoch value. Type is timestamp_t (Long). |
| metadata.loggers[].name | _system_name | Name of the system or logging subsystem generating the log entry. |  |
| metadata.log_name | _path | Log name. |  |
| metadata.uid | kuid | Observation unique ID. | Similar to uid, but specific to known entity tracking. Type is String. |
| device.ip | host_ip | Host IP address of the observed device. | Type is ip_t. |
| device.mac_addr | mac | Device MAC address. | IEEE MAC-48 format. Type is String. |
| device.vendor | vendor_mac | Device manufacturer. | Derived from OUI portion of MAC address. Type is String. |
| device.uid | mac | Unique identifier for the device. | MAC address used as device ID. Type is String. |
| duration | duration | Observation duration. | How long this device has been tracked. Convert to milliseconds. Type is Integer. |

### Conditional mapping:

| OCSF | Raw | Zeek Field Description | Evaluation Conditions |
| :---- | :---- | :---- | :---- |
| device.protocols[] | protocols | Observed network protocols. | Array of protocols used by this device. Type is Array of String. |
| device.type_id | protocols | Observed network protocols. | Determine device type from protocols: Contains "DNS::SERVER" → 3 (Server), contains "SSH::CLIENT" → 1 (Workstation), contains "DHCP::SERVER" → 4 (Network), contains "RADIUS::SERVER" → 5 (Security), else 0 (Unknown). Type is Integer. |
| status_id | last_active_session | Whether device is currently active. | If present and recent (within last hour), "1" (Active), else "2" (Inactive). Type is Integer. |

### Unmapped:

| OCSF | Raw | Zeek Field Description |
| :---- | :---- | :---- |
| observables[].value | host_vlan | Host VLAN ID. | VLAN tag if present. Type is Integer. |
| observables[].value | host_inner_vlan | Host inner VLAN ID. | Inner VLAN tag for Q-in-Q configurations. Type is Integer. |
| unmapped | num_conns | Number of observed connections. | Counter for connections involving this device. Type is Integer. |
| unmapped | long_conns | Count of long connections. | Number of persistent connections. Type is Integer. |
| unmapped | annotations | Observation annotations. | Additional metadata tags. Type is Array of String. |
| unmapped | last_active_session | Last seen session. | Connection UID of most recent activity. Type is String. |
| unmapped | last_active_interval | Last seen interval. | Time when device was last observed. Type is timestamp_t. |
| unmapped | device_roles | Inferred device roles based on traffic. | Array of functional roles observed. Type is Array of String. |