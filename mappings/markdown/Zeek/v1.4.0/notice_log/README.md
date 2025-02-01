# Event Dossier: Zeek notice.log

## Summary

**Description:** Maps Zeek notice.log to OCSF Detection Finding class

**Event References:**
- [OCSF Detection Finding Class v1.3.0](https://schema.ocsf.io/1.3.0/classes/detection_finding)
- [Zeek Notice Logs Documentation](https://docs.zeek.org/en/master/logs/weird-and-notice.html)
- [Zeek Notice Script](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/notice/main.zeek)

 ### OCSF Version: v1.4.0

## Static Value Mapping

| OCSF Field                     | Value  | Type    |
|--------------------------------|--------|---------|
| metadata.version               | "1.3.0" |         |
| category_uid                   | 2      | Integer |
| class_uid                      | 2004   | Integer |
| metadata.product.name          | "Zeek" |         |
| metadata.product.vendor_name   | "Zeek" |         |

## Direct Field Mapping

| OCSF Field                      | Zeek Field  | Description                           | Notes                          |
|---------------------------------|-------------|---------------------------------------|--------------------------------|
| time                            | ts          | Timestamp when notice occurred        | Convert to epoch timestamp     |
| metadata.logged_time            | _write_ts   | Timestamp when record was written     | Convert to epoch timestamp     |
| metadata.loggers[].name         | _system_name| Name of system generating record      |                                |
| metadata.log_name               | _path       | Log name ("notice")                   |                                |
| evidences[].src_endpoint.ip     | id.orig_h   | Originator IP address                 | Type: ip_t                     |
| evidences[].src_endpoint.port   | id.orig_p   | Originator port number                | Type: port_t                   |
| evidences[].dst_endpoint.ip     | id.resp_h   | Responder IP address                  | Type: ip_t                     |
| evidences[].dst_endpoint.port   | id.resp_p   | Responder port number                 | Type: port_t                   |
| finding_info.title              | note        | Notice::Type classification           |                                |
| message                         | msg         | Human-readable notice message         |                                |
| severity                        | severity.name| Textual severity level               |                                |
| severity_id                     | severity.level| Numeric severity identifier         | Verify level alignment         |
| observables[].value             | sub         | Additional context/observables        | Type: String                   |

## Conditional Mapping

| OCSF Field                      | Zeek Field   | Condition                           | Notes                                         |
|---------------------------------|--------------|-------------------------------------|-----------------------------------------------|
| status_id                       | suppress_for | If value > 0 → 3 (Suppressed)       | Maps suppression duration to OCSF status      |
| status_detail                   | actions      | Convert action list to human text   | Join actions with semicolons                  |
| finding_info.data_sources       | peer_descr   | If present → add as data source     |                                               |

## Unmapped Fields

| Zeek Field        | Description                            |
|-------------------|----------------------------------------|
| fuid              | File UID for file-related notices      |
| file_mime_type    | MIME type of associated files          |
| file_desc         | File context description               |
| remote_location.* | Geolocation data fields                |
| proto             | Transport protocol                     |
