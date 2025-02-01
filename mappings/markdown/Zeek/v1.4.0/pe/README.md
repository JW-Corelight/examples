# Event Dossier: Zeek pe.log
### Summary:
- **Description**: Maps Portable Executable (PE) characteristics to OCSF Data Security Finding
- **Event References**:
  - https://schema.ocsf.io/1.3.0/classes/data_security_finding
  - https://docs.zeek.org/en/master/scripts/policy/misc/pe.zeek.html

### OCSF Version: v1.3.0

### Static value mapping:
| OCSF Field                     | Value          | Type       |
|-------------------------------|----------------|------------|
| `metadata.version`            | "1.3.0"        |            |
| `category_uid`                | 2              | Integer    |
| `class_uid`                   | 2006           | Integer    |
| `activity_id`                 | 1              | Integer (Create) |
| `metadata.product.name`       | "Zeek"         |            |

### Direct field mapping:
| OCSF Field                     | Zeek Field              | Description                                | Notes                      |
|-------------------------------|-------------------------|--------------------------------------------|----------------------------|
| `file.created_time`           | `compile_ts`            | PE compilation timestamp                   | Convert to epoch timestamp |
| `file.xattributes.is_64bit`   | `is_64bit`              | 64-bit architecture flag                  | Boolean mapping            |
| `file.xattributes.aslr`      | `uses_aslr`             | ASLR implementation status                 | Boolean mapping            |
| `file.xattributes.dep`       | `uses_dep`              | Data Execution Prevention status           | Boolean mapping            |
| `file.xattributes.seh`       | `uses_seh`              | Structured Exception Handling usage        | Boolean mapping            |
| `file.xattributes.sections`  | `section_names`         | PE section names                          | Array preservation         |
| `file.xattributes.certs`     | `has_cert_table`        | Certificate table presence                | Boolean mapping            |
| `file.xattributes.debug`     | `has_debug_data`        | Debug data existence                       | Boolean mapping            |
| `file.is_system`             | `subsystem`             | Windows subsystem type                     | GUI/CUI mapping            |

### Extended PE characteristics mapping:
| OCSF File Attribute           | Zeek Field              | Type        |
|-------------------------------|-------------------------|-------------|
| `file.xattributes.imports`    | `has_import_table`      | Boolean     |
| `file.xattributes.exports`    | `has_export_table`      | Boolean     |
| `file.xattributes.integrity`  | `uses_code_integrity`   | Boolean     |
| `file.uid`                    | `id`                    | String      |

### Unmapped fields:
| Zeek Field               | Description                                  |
|--------------------------|----------------------------------------------|
| `machine`                | Target machine architecture                  |
| `os`                     | Required operating system version            |
