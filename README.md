# DnsAnalyticView

[WPA](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/windows-performance-analyzer) plugin to provide a better view for Microsoft-Windows-DNSServer/Analytical events.

## Sample

![wpa_sample](./Img/Sample.png)

## Event Fields

* Visible - Column shown in tables by default
* Hidden - Column can be added
* Implemented - Property implemented in DnsAnalyticEvent object but not built as a column
* Not implemented - Property not implemented in DnsAnalyticEvent due to lack of practicality or knowledge

| Field                      | Meaning                                                                                                                                                                                | Availability                    |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| CPU                        | ETW standard attribute, CPU core where the event was fired                                                                                                                             | Hidden                          |
| PID                        | ETW standard attribute, process ID that logged the event                                                                                                                               | Hidden                          |
| TID                        | ETW standard attribute, thread ID that logged the event                                                                                                                                | Hidden                          |
| EventID                    | ETW standard attribute, event ID                                                                                                                                                       | Hidden                          |
| Keywords                   | ETW standard attribute, ETW keyword                                                                                                                                                    | Hidden                          |
| Level                      | ETW standard attribute, event level                                                                                                                                                    | Hidden                          |
| MessageTemplate            | ETW standard attribute, template of the decoded message                                                                                                                                | Only cut out the [Operation]    |
| QNAME                      | DNS Query Name                                                                                                                                                                         | Visible                         |
| QTYPE                      | DNS Query Type                                                                                                                                                                         | Visible                         |
| XID                        | DNS Transaction ID                                                                                                                                                                     | Visible                         |
| QXID                       | Original query XID of a recursion query                                                                                                                                                | Visible                         |
| RCODE                      | DNS RCODE                                                                                                                                                                              | Visible                         |
| Flags                      | DNS Flags                                                                                                                                                                              | Visible                         |
| RD                         | RD (Recursion Desired) flag                                                                                                                                                            | Hidden                          |
| AA                         | AA (Authoritative Answer) flag                                                                                                                                                         | Hidden                          |
| AD                         | AD (Authentic Data, DNSSEC validated) flag                                                                                                                                             | Hidden                          |
| TCP                        | Is the query using TCP transport                                                                                                                                                       | Visible                         |
| DNSSEC                     | Is DNSSEC enabled query                                                                                                                                                                | Visible                         |
| Secure                     | Is secure DNS update                                                                                                                                                                   | Visible                         |
| Source                     | Source IP address                                                                                                                                                                      | Shown as [SrcAddr]              |
| Destination                | Destination IP address                                                                                                                                                                 | Shown as [DstAddr]              |
| InterfaceIP                | DNS server interface IP address, can be source or destination depending on event context                                                                                               | Shown as [SrcAddr] or [DstAddr] |
| Port                       | Port of a packet, can be source or destination port depending on event context                                                                                                         | Shown as [SrcPort] or [DstPort] |
| Zone                       | Zone a query falls under                                                                                                                                                               | Visible                         |
| Scope                      | Zone scope a query falls under                                                                                                                                                         | Visible                         |
| ZoneScope                  | Same as [Scope], but for update queries                                                                                                                                                | Shown as [Scope]                |
| PolicyName                 | DNS Policy a query matches                                                                                                                                                             | Visible                         |
| RecursionScope             | Recursion scope a recursion query falls under                                                                                                                                          | Visible                         |
| RecursionDepth             | Unknown, shown as "RemoteQueriesSent" in message                                                                                                                                       | Visible                         |
| ElapsedTime                | Time used for a query in milliseconds                                                                                                                                                  | Visible                         |
| CacheScope                 | Unknown                                                                                                                                                                                | Visible                         |
| Reason                     | Why a query fails                                                                                                                                                                      | Visible                         |
| AdditionalInfo             | Additional info, usually [VirtualizationInstance](https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsservervirtualizationinstance?view=windowsserver2022-ps) related | Visible                         |
| GUID                       | ID to correlate a query and the subsequent events it triggers                                                                                                                          | Visible                         |
| PacketData                 | DNS packet binary (UDP/TCP payload), possible to be decoded by Wireshark with a layer 4 pseudo header                                                                                  | Implemented                     |
| BufferSize                 | Size of [PacketData]                                                                                                                                                                   | Not implemented                 |
| StaleRecordsPresent        | Unknown                                                                                                                                                                                | Not implemented                 |
| QueriesAttached            | Unknown                                                                                                                                                                                | Not implemented                 |
| DataTag                    | Unknown                                                                                                                                                                                | Not implemented                 |
| EDNSCorrelationTag         | Unknown                                                                                                                                                                                | Not implemented                 |
| EDNSScopeName              | Unknown                                                                                                                                                                                | Not implemented                 |
| EDNSExtendedRCodeBits      | EDNS Extended RCODE                                                                                                                                                                    | Not implemented                 |
| EDNSFlags                  | EDNS flags                                                                                                                                                                             | Not implemented                 |
| EDNSUdpPayloadSize         | EDNS UDP payload size                                                                                                                                                                  | Hidden                          |
| EDNSVirtualizationInstance | Unknown                                                                                                                                                                                | Not implemented                 |
| EDNSDataTag                | Unknown                                                                                                                                                                                | Not implemented                 |
| CacheNodeName              | Unknown, DNSSEC related                                                                                                                                                                | Not implemented                 |
