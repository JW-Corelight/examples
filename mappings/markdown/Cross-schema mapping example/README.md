# OCSF Schema Mapping Examples

This directory contains example mappings between various security event schemas and the [Open Cybersecurity Schema Framework (OCSF)](https://github.com/ocsf). These examples are provided to assist organizations implementing OCSF in their security environments.

## Purpose

Security teams often need to transform data from various sources into a standardized format. These example mappings:

1. Demonstrate examples of how to map common security data formats to OCSF
2. Provide a starting point for your own mapping implementations

## Mapping Table Example

Below is an example mapping table showing how fields from a source schema map to OCSF fields. You can edit this table and add your specific mapping example here.

| OCSF Field | OpenTelemetry SemConv | Splunk CIM | ArcSight CEF | QRadar LEEF | Google UDM | Microsoft ASIM |
|------------|------------------------|------------|--------------|-------------|------------|----------------|
| activity_id | - | event_id (partial) | - | - | metadata.event_id (partial) | EventOriginalId (partial) |
| activity_name | span.name (partial - for trace spans only) | action, action_name (partial) | deviceAction (partial) | cat (contextual category) | metadata.event_type | EventType (requires schema match) |
| answers.class | - | answer | - | - | network.dns.answer.class | DnsAnswerClass |
| answers.flag_ids | - | - | - | - | - | - |
| answers.flags | - | - | - | - | - | - |
| answers.packet_uid | - | transaction_id (partial) | - | - | - | - |
| answers.rdata | - | answer | - | - | network.dns.answer.data | DnsResponseName |
| answers.ttl | - | ttl | - | - | - | - |
| answers.type | - | record_type | - | - | - | - |
| app_name | service.name | app | applicationProtocol | resource | principal.application | AppName |
| auth_type | - | authentication_method | - | - | security_result.auth_method | AuthenticationProtocol |
| auth_type_id | - | - | - | - | - | - |
| capabilities | - | - | - | - | - | - |
| category_name | - | category | deviceEventCategory | cat | metadata.product_event_type | EventCategory |
| category_uid | - | - | - | - | - | - |
| certificate_chain | tls.server_certificate | - | - | - | tls.certificate.chain | TlsServerCertificate |
| class_name | - | - | - | - | - | - |
| class_uid | - | - | - | - | - | - |
| client_dialects | - | - | - | - | - | - |
| client_hassh | - | - | - | - | network.tls.client_fingerprint | TlsClientHash |
| command | code.function | command | - | - | - | - |
| connection_info.boundary | - | - | - | - | - | - |
| connection_info.boundary_id | - | - | - | - | - | - |
| connection_info.direction | - | direction | - | - | - | - |
| connection_info.direction_id | - | - | proto | network.direction | FlowDirection |
| connection_info.protocol_name | net.protocol.name | protocol | app (partial) | - | - | - |
| connection_info.protocol_num | net.protocol.version | - | - | - | - | - |
| connection_info.protocol_ver | net.protocol.version | protocol_version | - | - | - | - |
| connection_info.protocol_ver_id | net.protocol.version (string representation) | protocol_version_id | - | protoVerId (custom extension) | network.protocol_version | ProtocolVersionId |
| connection_info.session | - | session_id | - | sessionID | network.session_id | SessionId |
| connection_info.session.count | - | session_count | - | - | network.connection_count | SessionCount |
| connection_info.session.created_time | - | start_time | - | startTime | network.session_start_time | SessionStartTime |
| connection_info.session.credential_uid | - | user_id | suid | userID | principal.user.userid | UserId |
| connection_info.session.expiration_reason | - | - | reason | - | security_result.details | SessionTerminationReason |
| connection_info.session.is_mfa | - | auth_factor | - | - | security_result.auth_factor.mfa | AuthenticationIsMfa |
| connection_info.session.is_remote | - | - | - | isRemote | principal.session.remote | IsRemoteSession |
| connection_info.session.is_vpn | - | - | - | vpnTunnel | network.tunnel_type (contextual) | NetworkProtocol (VPN detection) |
| connection_info.session.issuer | tls.client.issuer | - | - | - | tls.certificate.issuer | TlsCertificateIssuer |
| connection_info.session.terminal | - | - | - | termID | principal.session.terminal | SessionIdType |
| connection_info.session.uid | - | session_uid | - | sessionUID | network.session_id | SessionId |
| connection_info.session.uid_alt | - | - | - | - | network.alternate_session_id | AlternateSessionId |
| connection_info.session.uuid | - | session_uuid | - | - | network.session_uuid | SessionUuid |
| connection_info.tcp_flags | net.tcp.flags | tcp_flags | - | tcpFlags | network.tcp_flags | TcpFlags |
| connection_info.uid | net.connection.id | connection_uid | - | connUID | network.connection_id | ConnectionId |
| count | - | count | cnt | count | network.count | Count |
| dce_rpc | - | dce_rpc_opnum | - | dceRPC | rpc.opnum | DceRpcOpnum |
| dialect | - | smb_dialect | - | smbDialect | smb.dialect | SmbDialect |
| dst_endpoint.agent_list | - | dest_agents | - | agentList | target.agent.id | DstAgentId |
| dst_endpoint.autonomous_system | net.host.as.number | dest_asn | - | dstASN | network.asn | DstGeoAsn |
| dst_endpoint.domain | net.host.name | dest_nt_domain | dhost | domain | target.domain | DstDomainName |
| dst_endpoint.hostname | server.address, net.peer.name | dest, dest_host | destinationHostName | - | - | - |
| dst_endpoint.hw_info | - | dest_hw_vendor | dvendor | hwVendor | target.hardware.vendor | DstHardwareVendor |
| dst_endpoint.instance_uid | - | dest_instance_id | - | instanceID | target.instance.id | DstVmId |
| dst_endpoint.interface_name | net.host.interface | dest_interface | - | ifName | target.interface.name | DstInterfaceName |
| dst_endpoint.interface_uid | - | - | - | ifUID | target.interface.id | DstInterfaceGuid |
| dst_endpoint.intermediate_ips | - | x_forwarded_for | - | viaIPs | network.proxy_chain.ips | DstNatIpAddr |
| dst_endpoint.ip | net.sock.host.addr | dest_ip | dst | dst | network.dhcp.client_ip | DstIpAddr |
| dst_endpoint.location | net.host.geo.* | dest_geo_* | - | dstGeo | target.location | DstGeoCoordinates |
| dst_endpoint.mac | net.host.mac | dest_mac | dmac | dstMAC | target.mac | DstMacAddr |
| dst_endpoint.name | net.host.name | dest_host_name | dhost | dstHost | target.hostname | DstHostName |
| dst_endpoint.os | - | dest_os | deviceOS | osName | target.os.name | DstOsName |
| dst_endpoint.owner | - | dest_owner | - | owner | target.asset.owner | DstAssetOwner |
| dst_endpoint.port | net.sock.host.port | dest_port | dpt | dstPort | network.dhcp.client_port | DstPortNumber |
| dst_endpoint.proxy_endpoint | - | dest_proxy | - | proxyDst | network.proxy.endpoint | DstNatHostname |
| dst_endpoint.subnet_uid | - | dest_subnet | - | subnetUID | network.subnet.id | DstSubnetId |
| dst_endpoint.svc_name | - | dest_service | - | service | target.service.name | DstServiceName |
| dst_endpoint.type | net.host.type | dest_type | - | dstType | target.asset.type | DstDeviceType |
| dst_endpoint.type_id | - | - | - | dstTypeID | target.asset.type_id | DstDeviceTypeId |
| dst_endpoint.uid | - | dest_uid | - | dstUID | target.asset.id | DstDeviceId |
| dst_endpoint.vlan_uid | - | dest_vlan | - | vlanID | network.vlan.id | DstVlanId |
| dst_endpoint.vpc_uid | - | dest_vpc | - | vpcUID | network.vpc.id | DstVnetId |
| dst_endpoint.zone | net.host.zone | dest_zone | - | zone | target.zone | DstNetworkZone |
| duration | - | duration | - | - | - | - |
| end_time | - | end_time | end | endTime | network.session_end_time | EndTime |
| enrichments.created_time | - | enrichment_time | - | enrichTime | enrichment.time | EnrichmentCreatedTime |
| enrichments.data | - | enrichment_data | - | enrichData | enrichment.raw_data | EnrichmentData |
| enrichments.desc | - | enrichment_description | - | enrichDesc | enrichment.description | EnrichmentDescription |
| enrichments.name | - | enrichment_name | - | enrichName | enrichment.name | EnrichmentName |
| enrichments.provider | - | enrichment_provider | - | enrichProv | enrichment.provider | EnrichmentProvider |
| enrichments.reputation | - | enrichment_score | - | enrichRep | enrichment.reputation.score | EnrichmentReputationScore |
| enrichments.short_desc | - | enrichment_summary | - | enrichShort | enrichment.description_short | EnrichmentShortDesc |
| enrichments.src_url | - | enrichment_source | - | enrichSrc | enrichment.source_url | EnrichmentSourceUrl |
| enrichments.type | - | enrichment_type | - | enrichType | enrichment.type | EnrichmentType |
| enrichments.value | - | enrichment_value | - | enrichValue | enrichment.value | EnrichmentValue |
| file | - | file | - | - | file | File |
| file.accessed_time | - | file_access_time | fileAccessTime | - | - | - |
| file.accessor | - | user | suid | accessor | file.accessor | FileAccessor |
| file.attributes | - | file_attributes | fileAttr | - | file.attributes | FileAttributes |
| file.company_name | - | - | - | company | file.company | FileCompany |
| file.confidentiality | - | classification | - | fileClass | file.confidentiality | FileConfidentiality |
| file.confidentiality_id | - | classification_id | - | fileClassID | file.confidentiality_id | FileConfidentialityId |
| file.created_time | - | file_create_time | fileCreateTime | - | - | - |
| file.creator | - | file_creator | - | creator | file.creator | FileCreator |
| file.desc | - | comment | - | fileDesc | file.description | FileDescription |
| file.ext | file.extension | file_extension | fileExt | ext | file.extension | FileExtension |
| file.hashes | - | file_hash | fileHash | - | file.hash | FileHash |
| file.is_system | - | is_system_file | - | isSysFile | file.is_system | FileIsSystem |
| file.mime_type | file.mime_type | file_mime_type | - | mimeType | file.mime_type | FileMimeType |
| file.modified_time | - | file_modify_time | fileModTime | modTime | file.modified_time | FileModifiedTime |
| file.modifier | - | file_modifier | - | modifier | file.modifier | FileModifier |
| file.name | - | file_name | fileName | - | file.name | FileName |
| file.owner | - | file_owner | suid | owner | file.owner | FileOwner |
| file.parent_folder | file.directory | file_parent | - | parentDir | file.parent_directory | FileDirectory |
| file.path | - | file_path | filePath | - | - | - |
| file.product | - | file_version | - | fileProd | file.product | FileProduct |
| file.security_descriptor | - | - | - | secDesc | file.security_descriptor | FileSecurityDescriptor |
| file.signature | - | file_signature | - | sig | file.signature | FileSignature |
| file.size | - | file_size | fileSize | - | - | - |
| file.type | file.type | file_type | - | fileType | file.type | FileType |
| file.type_id | - | - | - | fileTypeID | file.type_id | FileTypeId |
| file.uid | - | file_uid | - | fileUID | file.id | FileId |
| file.version | - | file_version | - | fileVer | file.version | FileVersion |
| file.xattributes | - | - | - | xattr | file.xattributes | FileXAttributes |
| http_cookies.domain | http.request.header.cookie.domain | cookie_domain | - | cookieDomain | http.request.cookie.domain | HttpRequestCookieDomain |
| http_cookies.expiration_time | - | cookie_expires | - | cookieExpiry | http.request.cookie.expiration | HttpCookieExpirationTime |
| http_cookies.is_http_only | - | cookie_http_only | - | httpOnly | http.request.cookie.http_only | HttpCookieHttpOnly |
| http_cookies.is_secure | - | cookie_secure | - | secureFlag | http.request.cookie.secure | HttpCookieSecure |
| http_cookies.name | http.request.header.cookie.name | cookie_name | - | cookieName | http.request.cookie.name | HttpRequestCookieName |
| http_cookies.path | - | cookie_path | - | cookiePath | http.request.cookie.path | HttpCookiePath |
| http_cookies.samesite | - | cookie_samesite | - | sameSite | http.request.cookie.samesite | HttpCookieSameSite |
| http_cookies.value | http.request.header.cookie.value | cookie_value | - | cookieValue | http.request.cookie.value | HttpRequestCookieValue |
| http_request.args | http.request.params | http_query | request | args | http.request.parameters | HttpRequestParameters |
| http_request.http_headers | http.request.header.* | - | request.header.* | - | - | - |
| http_request.http_method | http.request.method | http_method | requestMethod | - | http.request.method | HttpRequestMethod |
| http_request.length | http.request.body.size | http_content_length | bytesIn | contentLength | http.request.size | HttpRequestLength |
| http_request.referrer | http.request.header.referer | http_referrer | requestClientApplication | referer | http.request.referrer | HttpRequestReferrer |
| http_request.uid | - | http_request_id | - | reqUID | http.request.id | HttpRequestId |
| http_request.url | http.url | url | request | url | http.request.url | UrlOriginal |
| http_request.user_agent | http.user_agent | http_user_agent | requestClientApplication | userAgent | http.request.user_agent | HttpRequestUserAgent |
| http_request.version | http.flavor | http_version | - | httpVer | http.version | HttpVersion |
| http_request.x_forwarded_for | http.request.header.x-forwarded-for | x_forwarded_for | - | xForward | http.request.x_forwarded_for | XForwardedFor |
| http_response.code | http.response.status_code | status_code (partial) | - | - | - | - |
| http_response.content_type | http.response.header.content-type | http_content_type | - | contentType | http.response.content_type | HttpResponseContentType |
| http_response.http_headers | http.response.header.* | - | - | respHeaders | http.response.headers | HttpResponseHeaders |
| http_response.latency | http.server.duration | response_time | - | latency | http.response.latency | HttpResponseLatency |
| http_response.length | http.response.body.size | http_response_length | bytesOut | contentLength | http.response.size | HttpResponseLength |
| http_response.message | http.response.status_text | http_status_message | - | statusMsg | http.response.message | HttpStatusMessage |
| http_response.status | http.response.status_code | http_status | - | statusCode | http.response.status | HttpStatusCode |
| identifier_cookie | http.client_cookie | session_cookie | - | sessCookie | http.cookie.id | HttpCookieId |
| is_renewal | - | dhcp_is_renewal | - | isRenew | dhcp.is_renewal | DhcpIsRenewal |
| ja4_fingerprint_list.section_a | - | ja4_a | - | ja4A | tls.ja4.section_a | TlsJa4SectionA |
| ja4_fingerprint_list.section_b | - | ja4_b | - | ja4B | tls.ja4.section_b | TlsJa4SectionB |
| ja4_fingerprint_list.section_c | - | ja4_c | - | ja4C | tls.ja4.section_c | TlsJa4SectionC |
| ja4_fingerprint_list.section_d | - | ja4_d | - | ja4D | tls.ja4.section_d | TlsJa4SectionD |
| ja4_fingerprint_list.type | - | ja4_type | - | ja4Type | tls.ja4.type | TlsJa4Type |
| ja4_fingerprint_list.type_id | - | - | - | ja4TypeID | tls.ja4.type_id | TlsJa4TypeId |
| ja4_fingerprint_list.value | - | ja4 | - | ja4Full | tls.ja4.full | TlsJa4 |
| lease_dur | - | dhcp_lease_time | - | leaseDur | dhcp.lease_duration | DhcpLeaseDuration |
| message | exception.message (partial) | message | msg | - | - | - |
| metadata.correlation_uid | trace_id | correlation_id | externalId | corrUID | metadata.event_correlation_id | CorrelationId |
| metadata.event_code | - | event_code | eventId | eventCode | metadata.event_code | EventCode |
| metadata.extensions | - | extensions | - | ext | metadata.extensions | Extensions |
| metadata.labels | resource.labels | tags | - | labels | metadata.labels | Labels |
| metadata.log_level | log.severity | severity | severity | logLevel | metadata.severity | EventSeverity |
| metadata.log_name | log.name | source | deviceEventClassId | logName | metadata.log_name | LogName |
| metadata.log_provider | service.provider | vendor | deviceVendor | logProv | metadata.product_name | EventProduct |
| metadata.log_version | service.version | sourcetype_version | deviceVersion | logVer | metadata.product_version | EventProductVersion |
| metadata.logged_time | log.timestamp | _time | end | loggedTime | metadata.event_timestamp | EventGeneratedTime |
| metadata.loggers | - | host | deviceHostName | loggers | metadata.logger | LoggingSystem |
| metadata.modified_time | - | modified_time | - | modTime | metadata.modified_time | EventModifiedTime |
| metadata.original_time | - | _indextime | start | origTime | metadata.original_timestamp | EventOriginalTime |
| metadata.processed_time | - | processed_time | - | procTime | metadata.processed_time | EventProcessedTime |
| metadata.product | service.name, telemetry.sdk.name | vendor_product | - | devVendor | metadata.product_name | EventProduct |
| metadata.profiles | - | profiles | - | profiles | metadata.profiles | EventProfiles |
| metadata.sequence | - | sequence | - | seq | metadata.sequence | EventSequence |
| metadata.tenant_uid | - | tenant_id | - | tenantUID | metadata.tenant_id | TenantId |
| metadata.uid | span_id | event_uid | externalId | eventUID | metadata.event_id | EventId |
| metadata.version | service.version, telemetry.sdk.version | - | - | devVersion | metadata.product_version | EventProductVersion |
| observables.name | - | observable_name | - | obsName | observable.name | ObservableName |
| observables.reputation | - | observable_reputation | - | obsRep | observable.reputation.score | ObservableReputation |
| observables.type | - | observable_type | - | obsType | observable.type | ObservableType |
| observables.type_id | - | observable_type_id | - | obsTypeID | observable.type_id | ObservableTypeId |
| observables.value | - | observable_value | - | obsValue | observable.value | ObservableValue |
| open_type | - | file_open_mode | - | openMode | file.open_type | FileOpenType |
| protocol_ver | net.protocol.version | protocol_version | - | protoVer | network.protocol_version | ProtocolVersion |
| proxy.agent_list | - | proxy_agents | - | proxyAgents | proxy.agent.ids | ProxyAgentIds |
| proxy.autonomous_system | net.hop.as.number | proxy_asn | - | proxyASN | proxy.asn | ProxyAsn |
| proxy.domain | net.hop.name | proxy_domain | - | proxyDomain | proxy.domain | ProxyDomain |
| proxy.hostname | net.hop.hostname | proxy_host | - | proxyHost | proxy.hostname | ProxyHostName |
| proxy.hw_info | - | proxy_hw_vendor | - | proxyHW | proxy.hardware.vendor | ProxyHwVendor |
| proxy.instance_uid | - | proxy_instance_id | - | proxyInstID | proxy.instance.id | ProxyInstanceId |
| proxy.interface_name | net.hop.interface | proxy_interface | - | proxyIf | proxy.interface.name | ProxyInterface |
| proxy.interface_uid | - | - | - | proxyIfUID | proxy.interface.id | ProxyInterfaceId |
| proxy.intermediate_ips | net.hop.ips | x_forwarded_for | - | viaIPs | proxy.chain.ips | ProxyChainAddresses |
| proxy.ip | net.hop.ip | proxy_ip | - | proxyIP | proxy.ip | ProxyIpAddr |
| proxy.location | net.hop.geo.* | proxy_geo_* | - | proxyGeo | proxy.location | ProxyGeoLocation |
| proxy.mac | net.hop.mac | proxy_mac | - | proxyMAC | proxy.mac | ProxyMacAddr |
| proxy.name | net.hop.name | proxy_name | - | proxyName | proxy.name | ProxyName |
| proxy.os | - | proxy_os | - | proxyOS | proxy.os.name | ProxyOsName |
| proxy.owner | - | proxy_owner | - | proxyOwner | proxy.owner | ProxyOwner |
| proxy.port | net.hop.port | proxy_port | - | proxyPort | proxy.port | ProxyPort |
| proxy.proxy_endpoint | - | proxy_endpoint | - | proxyEP | proxy.endpoint | ProxyEndpoint |
| proxy.subnet_uid | - | proxy_subnet | - | proxySubnet | proxy.subnet.id | ProxySubnetId |
| proxy.svc_name | - | proxy_service | - | proxySvc | proxy.service.name | ProxyServiceName |
| proxy.type | net.hop.type | proxy_type | - | proxyType | proxy.type | ProxyType |
| proxy.type_id | - | - | - | proxyTypeID | proxy.type_id | ProxyTypeId |
| proxy.uid | - | proxy_uid | - | proxyUID | proxy.id | ProxyId |
| proxy.vlan_uid | - | proxy_vlan | - | proxyVLAN | network.vlan.id | ProxyVlanId |
| proxy.vpc_uid | - | proxy_vpc | - | proxyVPC | network.vpc.id | ProxyVnetId |
| proxy.zone | net.hop.zone | proxy_zone | - | proxyZone | proxy.zone | ProxyZone |
| query_time | - | query_time | - | qTime | dns.query.time | DnsQueryTime |
| query.class | - | dns_class | - | dnsClass | dns.query.class | DnsQueryClass |
| query.hostname | db.statement (partial) | query | - | - | network.dns.query.name | DnsQuery |
| query.opcode | - | dns_opcode | - | dnsOpCode | dns.query.opcode | DnsOpcode |
| query.opcode_id | - | - | - | - | dns.query.opcode_id | DnsOpcodeId |
| query.packet_uid | - | transaction_id | - | pktUID | dns.query.id | DnsTransactionId |
| query.type | - | query_type | - | - | - | - |
| raw_data | - | _raw | - | rawData | raw.log | OriginalData |
| rcode | dns.rcode | dns_rcode | - | dnsRcode | dns.response.rcode | DnsResponseCode |
| rcode_id | - | dns_rcode_id | - | dnsRcodeID | dns.response.rcode_id | DnsResponseCodeId |
| relay | - | dhcp_relay | - | dhcpRelay | dhcp.relay | DhcpRelayAgent |
| remote_display | - | rdp_display | - | rdpDisp | rdp.display | RdpDisplay |
| request | http.request | http_request | request | req | http.request | HttpRequest |
| response | http.response | http_response | - | resp | http.response | HttpResponse |
| response_time | http.server.duration | response_time | - | respTime | http.response.latency | HttpResponseLatency |
| server_hassh | - | hassh_server | - | hasshSrv | ssh.server.hassh | SshServerHassh |
| severity | logs.severity | severity | severity (header) | sev | security_result.severity | EventSeverity |
| severity_id | - | severity_id | severity (header) | | | |
| share | - | file_share | - | fileShare | file.share | FileShare |
| share_type | - | share_type | - | shareType | file.share.type | FileShareType |
| share_type_id | - | share_type_id | - | shareTypeID | file.share.type_id | FileShareTypeId |
| src_endpoint.agent_list | - | src_agents | - | agentList | principal.agent.id | SrcAgentId |
| src_endpoint.autonomous_system | net.peer.as.number | src_asn | - | srcASN | network.asn | SrcGeoAsn |
| src_endpoint.domain | net.peer.name | src_nt_domain | shost | domain | principal.domain | SrcDomainName |
| src_endpoint.hostname | client.address, net.peer.name | src, src_host | sourceHostName | - | - | - |
| src_endpoint.hw_info | - | src_hw_vendor | svendor | hwVendor | principal.hardware.vendor | SrcHardwareVendor |
| src_endpoint.instance_uid | - | src_instance_id | - | instanceID | principal.instance.id | SrcVmId |
| src_endpoint.interface_name | net.peer.interface | src_interface | - | ifName | principal.interface.name | SrcInterfaceName |
| src_endpoint.interface_uid | - | - | - | ifUID | principal.interface.id | SrcInterfaceGuid |
| src_endpoint.intermediate_ips | - | x_forwarded_for | - | viaIPs | network.proxy_chain.ips | SrcNatIpAddr |
| src_endpoint.ip | net.sock.peer.addr | src_ip | src | src | principal.ip | SrcIpAddr |
| src_endpoint.location | net.peer.geo.* | src_geo_* | - | srcGeo | principal.location | SrcGeoCoordinates |
| src_endpoint.mac | net.peer.mac | src_mac | smac | srcMAC | principal.mac | SrcMacAddr |
| src_endpoint.name | net.peer.name | src_host_name | shost | srcHost | principal.hostname | SrcHostName |
| src_endpoint.os | - | src_os | deviceOS | osName | principal.os.name | SrcOsName |
| src_endpoint.owner | - | src_owner | - | owner | principal.asset.owner | SrcAssetOwner |
| src_endpoint.port | net.sock.peer.port | src_port | spt | srcPort | principal.port | SrcPortNumber |
| src_endpoint.proxy_endpoint | - | src_proxy | - | proxySrc | network.proxy.endpoint | SrcNatHostname |
| src_endpoint.subnet_uid | - | src_subnet | - | subnetUID | network.subnet.id | SrcSubnetId |
| src_endpoint.svc_name | - | src_service | - | service | principal.service.name | SrcServiceName |
| src_endpoint.type | net.peer.type | src_type | - | srcType | principal.asset.type | SrcDeviceType |
| src_endpoint.type_id | - | - | - | srcTypeID | principal.asset.type_id | SrcDeviceTypeId |
| src_endpoint.uid | - | src_uid | - | srcUID | principal.asset.id | SrcDeviceId |
| src_endpoint.vlan_uid | - | src_vlan | - | vlanID | network.vlan.id | SrcVlanId |
| src_endpoint.vpc_uid | - | src_vpc | - | vpcUID | network.vpc.id | SrcVnetId |
| src_endpoint.zone | net.peer.zone | src_zone | - | zone | principal.zone | SrcNetworkZone |
| start_time | - | start_time | start | startTime | network.session_start_time | StartTime |
| status | http.status_text | http_status_message | - | statusMsg | http.response.message | HttpStatusMessage |
| status_code | http.status_code | http_status | - | statusCode | http.response.status | HttpStatusCode |
| status_detail | - | - | - | statusDetail | http.response.detail | HttpStatusDetail |
| status_id | - | http_status_id | - | statusID | http.response.status_id | HttpStatusId |
| time | - | _time | rt, end, start (depending on context) | devTime | metadata.event_timestamp | EventStartTime |
| timezone_offset | - | _tz | - | tzOffset | metadata.timezone_offset | EventTimeZoneOffset |
| tls.alert | tls.client.alert | - | - | tlsAlert | network.tls.alert | TlsAlert |
| tls.certificate | tls.server.certificate | - | certificate | tlsCert | tls.certificate | TlsServerCertificate |
| tls.certificate_chain | tls.server.certificate_chain | - | - | - | tls.certificate.chain | TlsCertificateChain |
| tls.cipher | tls.cipher | - | - | tlsCipher | tls.cipher_suite | TlsCipherSuite |
| tls.client_ciphers | tls.client.ciphers | - | - | - | tls.client.ciphers | TlsClientCiphers |
| tls.handshake_dur | - | tls_handshake_time | duration | tlsHSDur | tls.handshake_duration | TlsHandshakeDuration |
| tls.ja3_hash | - | ja3_hash | - | ja3Hash | tls.client.ja3 | TlsClientJa3Hash |
| tls.ja3s_hash | - | ja3s_hash | - | ja3sHash | tls.server.ja3s | TlsServerJa3sHash |
| tls.key_length | tls.server.key_length | - | - | tlsKeyLen | tls.key_length | TlsKeyLength |
| tls.sans | tls.server.san | - | - | tlsSANs | tls.certificate.sans | TlsCertificateSans |
| tls.server_ciphers | tls.server.ciphers | - | - | - | tls.server.ciphers | TlsServerCiphers |
| tls.sni | tls.server.name | tls_sni | - | tlsSNI | tls.sni | TlsSni |
| tls.tls_extension_list | tls.extensions | - | - | tlsExt | tls.extensions | TlsExtensions |
| tls.version | tls.version | tls_version | - | tlsVer | tls.version | TlsVersion |
| traffic.bytes | network.bytes | bytes_total | bytes | bytesTotal | network.bytes | TotalBytes |
| traffic.bytes_in | network.bytes.received | bytes_in | bytesIn | srcBytes | network.sent_bytes | BytesSent |
| traffic.bytes_out | network.bytes.sent | bytes_out | bytesOut | dstBytes | network.received_bytes | BytesReceived |
| traffic.chunks | - | - | - | - | network.chunk_count | ChunkCount |
| traffic.chunks_in | - | chunks_in | - | chunksIn | network.received_chunks | ChunksReceived |
| traffic.chunks_out | - | chunks_out | - | chunksOut | network.sent_chunks | ChunksSent |
| traffic.packets | - | packets | - | - | - | - |
| traffic.packets_in | network.packets.received | packets_in | pktsIn | packetsIn | network.received_packets | PacketsReceived |
| traffic.packets_out | network.packets.sent | packets_out | pktsOut | packetsOut | network.sent_packets | PacketsSent |
| url.categories | - | url_category | - | urlCat | url.category | UrlCategory |
| url.category_ids | - | url_category_id | - | urlCatID | url.category_id | UrlCategoryId |
| url.domain | url.domain | url_domain | destinationDnsDomain | domain | url.domain | UrlDomain |
| url.hostname | url.host | url_host | destinationDnsHost | host | url.hostname | UrlHostname |
| url.path | url.path | url_path | request | path | url.path | UrlPath |
| url.port | url.port | url_port | destinationPort | port | url.port | UrlPort |
| url.query_string | url.query | url_query | requestQuery | query | url.query | UrlQuery |
| url.resource_type | - | url_resource_type | - | resType | url.resource_type | UrlResourceType |
| url.scheme | url.scheme | url_scheme | - | scheme | url.scheme | UrlScheme |
| url.subdomain | - | url_subdomain | - | subDomain | url.subdomain | UrlSubdomain |
| url.url_string | url.full | url | request | fullUrl | url.full | UrlOriginal |
| - | enduser.id, user.id | user | suser (source user), duser (destination user) | usrName | principal.user.userid | UserName |
