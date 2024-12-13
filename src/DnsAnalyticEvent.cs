using KzA.DNS;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace DnsAnalyticView
{
    public class DnsAnalyticEvent : IKeyedDataType<Guid>, IComparable<Guid>
    {
        public static readonly Guid Microsoft_Windows_DNSServer = new Guid("eb79061a-a566-4698-9119-3ed2807060e7");

        internal static DateTime TraceStartTime = DateTime.MinValue;

        public static readonly Dictionary<int, DnsAnalyticOperation> Operations = new Dictionary<int, DnsAnalyticOperation>
        {
            { 256, DnsAnalyticOperation.QUERY_RECEIVED },
            { 257, DnsAnalyticOperation.RESPONSE_SUCCESS },
            { 258, DnsAnalyticOperation.RESPONSE_FAILURE },
            { 259, DnsAnalyticOperation.IGNORED_QUERY },
            { 260, DnsAnalyticOperation.RECURSE_QUERY_OUT },
            { 261, DnsAnalyticOperation.RECURSE_RESPONSE_IN },
            { 262, DnsAnalyticOperation.RECURSE_QUERY_TIMEOUT },
            { 263, DnsAnalyticOperation.DYN_UPDATE_RECV },
            { 264, DnsAnalyticOperation.DYN_UPDATE_RESPONSE },
            { 265, DnsAnalyticOperation.IXFR_REQ_OUT },
            { 266, DnsAnalyticOperation.IXFR_REQ_RECV },
            { 267, DnsAnalyticOperation.IXFR_RESP_OUT },
            { 268, DnsAnalyticOperation.IXFR_RESP_RECV },
            { 269, DnsAnalyticOperation.AXFR_REQ_OUT },
            { 270, DnsAnalyticOperation.AXFR_REQ_RECV },
            { 271, DnsAnalyticOperation.AXFR_RESP_OUT },
            { 272, DnsAnalyticOperation.AXFR_RESP_RECV },
            { 273, DnsAnalyticOperation.XFR_NOTIFY_RECV },
            { 274, DnsAnalyticOperation.XFR_NOTIFY_OUT },
            { 275, DnsAnalyticOperation.XFR_NOTIFY_ACK_IN },
            { 276, DnsAnalyticOperation.XFR_NOTIFY_ACK_OUT },
            { 277, DnsAnalyticOperation.DYN_UPDATE_FORWARD },
            { 278, DnsAnalyticOperation.DYN_UPDATE_RESPONSE_IN },
            { 279, DnsAnalyticOperation.INTERNAL_LOOKUP_CNAME },
            { 280, DnsAnalyticOperation.INTERNAL_LOOKUP_ADDITIONAL },
            { 281, DnsAnalyticOperation.RRL_TO_BE_DROPPED_RESPONSE },
            { 282, DnsAnalyticOperation.RRL_TO_BE_TRUNCATED_RESPONSE },
            { 283, DnsAnalyticOperation.RRL_TO_BE_LEAKED_RESPONSE },
            { 284, DnsAnalyticOperation.RESPONSE_SUCCESS },
            { 285, DnsAnalyticOperation.RESPONSE_FAILURE },
            { 286, DnsAnalyticOperation.RECURSE_ALIAS_FAILURE },
            { 287, DnsAnalyticOperation.QUERY_RECEIVED },
            { 288, DnsAnalyticOperation.DNSSEC_VALIDATION_FAILURE },
            { 289, DnsAnalyticOperation.RECURSE_QUERY_OUT },
            { 290, DnsAnalyticOperation.RECURSE_RESPONSE_IN },
            { 291, DnsAnalyticOperation.RECURSE_QUERY_TIMEOUT },
        };

        public DnsAnalyticEvent(TraceEvent e, long startTime, bool LoadPacketData = false)
        {
            if (e.ProviderGuid != Microsoft_Windows_DNSServer || e.Channel != (TraceEventChannel)16) throw new ArgumentException("Not DNS Analytic event");
            Operation = Operations.TryGetValue((int)e.ID, out var op) ? op
                : DnsAnalyticOperation.UNKNOWN;
            Timestamp = e.TimeStamp;
            RelativeTime = new Timestamp((e.TimeStamp.Ticks - startTime) * 100);
            CPU = e.ProcessorNumber;
            PID = e.ProcessID;
            TID = e.ThreadID;
            EventID = e.ID;
            Level = e.Level;
            Keywords = e.Keywords;

            QNAME = e.PayloadByName(nameof(QNAME)) as string;
            QTYPE = (RRType)e.UIntPayloadByName(nameof(QTYPE));
            XID = e.UIntPayloadByName(nameof(XID));
            QXID = e.UIntPayloadByName(nameof(QXID));
            RCODE = (RCODE)e.UIntPayloadByName(nameof(RCODE));
            Flags = e.UIntPayloadByName(nameof(Flags));
            RD = e.BooleanPayloadByName(nameof(RD));
            AA = e.BooleanPayloadByName(nameof(AA));
            AD = e.BooleanPayloadByName(nameof(AD));
            Secure = e.BooleanPayloadByName(nameof(Secure));
            TCP = e.BooleanPayloadByName(nameof(TCP));
            DNSSEC = e.BooleanPayloadByName(nameof(DNSSEC));
            Zone = e.PayloadByName(nameof(Zone)) as string;
            Scope = e.PayloadByName(nameof(Scope)) as string;
            if (e.PayloadNames.Contains("ZoneScope")) Scope = e.PayloadByName("ZoneScope") as string;         // ZoneScope is only used in DYN_UPDATE events
            PolicyName = e.PayloadByName(nameof(PolicyName)) as string;
            RecursionScope = e.PayloadByName(nameof(RecursionScope)) as string;
            RecursionDepth = e.UIntPayloadByName(nameof(RecursionDepth));
            ElapsedTime = e.UIntPayloadByName(nameof(ElapsedTime));
            CacheScope = e.PayloadByName(nameof(CacheScope)) as string;
            Reason = e.PayloadByName(nameof(Reason)) as string;
            if (e.PayloadNames.Contains("AliasFailureReason")) Reason = e.PayloadByName("AliasFailureReason") as string;
            AdditionalInfo = e.PayloadByName(nameof(AdditionalInfo)) as string;
            CorrelationID = new Guid((e.PayloadByName("GUID") as string) ?? "00000000-0000-0000-0000-000000000000");
            if (e.PayloadNames.Contains("QueryGUID")) CorrelationID = new Guid((e.PayloadByName("QueryGUID") as string) ?? "00000000-0000-0000-0000-000000000000");
            EDNSUdpPayloadSize = e.UIntPayloadByName(nameof(EDNSUdpPayloadSize));

            switch (Operation)
            {
                case DnsAnalyticOperation.QUERY_RECEIVED:
                case DnsAnalyticOperation.DYN_UPDATE_RECV:
                case DnsAnalyticOperation.INTERNAL_LOOKUP_CNAME:
                case DnsAnalyticOperation.INTERNAL_LOOKUP_ADDITIONAL:
                case DnsAnalyticOperation.RECURSE_ALIAS_FAILURE:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case DnsAnalyticOperation.RESPONSE_SUCCESS:
                case DnsAnalyticOperation.RESPONSE_FAILURE:
                case DnsAnalyticOperation.RRL_TO_BE_DROPPED_RESPONSE:
                case DnsAnalyticOperation.RRL_TO_BE_TRUNCATED_RESPONSE:
                case DnsAnalyticOperation.RRL_TO_BE_LEAKED_RESPONSE:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case DnsAnalyticOperation.IGNORED_QUERY:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case DnsAnalyticOperation.RECURSE_QUERY_OUT:
                case DnsAnalyticOperation.RECURSE_QUERY_TIMEOUT:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case DnsAnalyticOperation.RECURSE_RESPONSE_IN:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case DnsAnalyticOperation.IXFR_REQ_OUT:
                case DnsAnalyticOperation.AXFR_REQ_OUT:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case DnsAnalyticOperation.IXFR_REQ_RECV:
                case DnsAnalyticOperation.AXFR_REQ_RECV:
                case DnsAnalyticOperation.XFR_NOTIFY_RECV:
                case DnsAnalyticOperation.XFR_NOTIFY_ACK_IN:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case DnsAnalyticOperation.IXFR_RESP_OUT:
                case DnsAnalyticOperation.AXFR_RESP_OUT:
                //case DnsAnalyticOperation.XFR_NOTIFY_OUT:
                case DnsAnalyticOperation.XFR_NOTIFY_ACK_OUT:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                // Well, in Windows Server 2025 manifest, XFR_NOTIFY_OUT uses "Source" field as destination address
                case DnsAnalyticOperation.XFR_NOTIFY_OUT:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case DnsAnalyticOperation.IXFR_RESP_RECV:
                case DnsAnalyticOperation.AXFR_RESP_RECV:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
                case DnsAnalyticOperation.DYN_UPDATE_FORWARD:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("ForwardInterfaceIP") as string, out var ForwardInterfaceIPAddr) ? ForwardInterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case DnsAnalyticOperation.DYN_UPDATE_RESPONSE_IN:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
                case DnsAnalyticOperation.DYN_UPDATE_RESPONSE:
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
            }

            if (LoadPacketData && e.PayloadNames.Contains(nameof(PacketData))) PacketData = (byte[])e.PayloadByName(nameof(PacketData));
        }
        public DnsAnalyticOperation Operation { get; set; }
        public DateTime Timestamp { get; set; }
        public Timestamp RelativeTime { get; set; }
        public int CPU { get; set; }
        public int PID { get; set; }
        public int TID { get; set; }
        public TraceEventID EventID { get; set; }
        public TraceEventKeyword Keywords { get; set; }
        public TraceEventLevel Level { get; set; }
        public string? QNAME { get; set; } = string.Empty;
        public RRType QTYPE { get; set; } = 0;
        public uint XID { get; set; } = 0;
        public uint QXID { get; set; } = 0;
        public RCODE RCODE { get; set; } = 0;
        public uint Flags { get; set; } = 0;
        public bool RD { get; set; } = false;
        public bool AA { get; set; } = false;
        public bool AD { get; set; } = false;
        public bool TCP { get; set; } = false;
        public bool DNSSEC { get; set; } = false;
        public bool Secure { get; set; } = false;
        public IPAddress SrcAddr { get; set; } = IPAddress.Any;
        public IPAddress DstAddr { get; set; } = IPAddress.Any;
        public IPAddress RemoteAddr
        {
            get
            {
                switch (Operation)
                {
                    case DnsAnalyticOperation.QUERY_RECEIVED:
                    case DnsAnalyticOperation.DYN_UPDATE_RECV:
                    case DnsAnalyticOperation.RECURSE_RESPONSE_IN:
                    case DnsAnalyticOperation.IXFR_REQ_RECV:
                    case DnsAnalyticOperation.IXFR_RESP_RECV:
                    case DnsAnalyticOperation.AXFR_REQ_RECV:
                    case DnsAnalyticOperation.AXFR_RESP_RECV:
                    case DnsAnalyticOperation.XFR_NOTIFY_RECV:
                    case DnsAnalyticOperation.XFR_NOTIFY_ACK_IN:
                    case DnsAnalyticOperation.DYN_UPDATE_RESPONSE_IN:
                    case DnsAnalyticOperation.INTERNAL_LOOKUP_CNAME:
                    case DnsAnalyticOperation.INTERNAL_LOOKUP_ADDITIONAL:
                    case DnsAnalyticOperation.RECURSE_ALIAS_FAILURE:
                        return SrcAddr;
                    case DnsAnalyticOperation.RESPONSE_SUCCESS:
                    case DnsAnalyticOperation.RESPONSE_FAILURE:
                    case DnsAnalyticOperation.IGNORED_QUERY:
                    case DnsAnalyticOperation.RECURSE_QUERY_OUT:
                    case DnsAnalyticOperation.RECURSE_QUERY_TIMEOUT:
                    case DnsAnalyticOperation.DYN_UPDATE_RESPONSE:
                    case DnsAnalyticOperation.IXFR_REQ_OUT:
                    case DnsAnalyticOperation.IXFR_RESP_OUT:
                    case DnsAnalyticOperation.AXFR_REQ_OUT:
                    case DnsAnalyticOperation.AXFR_RESP_OUT:
                    case DnsAnalyticOperation.XFR_NOTIFY_OUT:
                    case DnsAnalyticOperation.XFR_NOTIFY_ACK_OUT:
                    case DnsAnalyticOperation.DYN_UPDATE_FORWARD:
                    case DnsAnalyticOperation.RRL_TO_BE_DROPPED_RESPONSE:
                    case DnsAnalyticOperation.RRL_TO_BE_TRUNCATED_RESPONSE:
                    case DnsAnalyticOperation.RRL_TO_BE_LEAKED_RESPONSE:
                        return DstAddr;
                    default:
                        return IPAddress.Any;
                }
            }
        }
        public uint SrcPort { get; set; } = 53;
        public uint DstPort { get; set; } = 53;
        public string? Zone { get; set; } = string.Empty;
        public string? Scope { get; set; } = string.Empty;
        public string? PolicyName { get; set; } = string.Empty;
        public string? RecursionScope { get; set; } = string.Empty;
        public uint RecursionDepth { get; set; } = 0;
        public uint ElapsedTime { get; set; } = 0;
        public string? CacheScope { get; set; } = string.Empty;
        public string? Reason { get; set; } = string.Empty;
        public string? AdditionalInfo { get; set; } = string.Empty;
        public Guid CorrelationID { get; set; } = Guid.Empty;
        public byte[] PacketData { get; set; } = Array.Empty<byte>();
        public uint EDNSUdpPayloadSize { get; set; } = 0;

        public Guid GetKey() => Microsoft_Windows_DNSServer;

        public int CompareTo(Guid other)
        {
            return Microsoft_Windows_DNSServer.CompareTo(other);
        }

        /* Rarely used or unknown usage fields 
        public uint? BufferSize { get; set; } = 0;
        public string? StaleRecordsPresent { get; set; } = string.Empty;
        public uint? QueriesAttached { get; set; } = 0;
        public ulong? DataTag { get; set; } = 0;
        public Guid EDNSCorrelationTag { get; set; } = Guid.Empty;
        public string? EDNSScopeName { get; set; } = string.Empty;
        public byte? EDNSExtendedRCodeBits { get; set; } = 0;
        public uint? EDNSFlags { get; set; } = 0;
        public string? EDNSVirtualizationInstance { get; set; } = string.Empty;
        public ulong? EDNSDataTag { get; set; } = 0;
        public string? CacheNodeName { get; set; } = string.Empty;
        */
    }
    public enum DnsAnalyticOperation
    {
        QUERY_RECEIVED,
        RESPONSE_SUCCESS,
        RESPONSE_FAILURE,
        IGNORED_QUERY,
        RECURSE_QUERY_OUT,
        RECURSE_RESPONSE_IN,
        RECURSE_QUERY_TIMEOUT,
        DYN_UPDATE_RECV,
        DYN_UPDATE_RESPONSE,
        IXFR_REQ_OUT,
        IXFR_REQ_RECV,
        IXFR_RESP_OUT,
        IXFR_RESP_RECV,
        AXFR_REQ_OUT,
        AXFR_REQ_RECV,
        AXFR_RESP_OUT,
        AXFR_RESP_RECV,
        XFR_NOTIFY_RECV,
        XFR_NOTIFY_OUT,
        XFR_NOTIFY_ACK_IN,
        XFR_NOTIFY_ACK_OUT,
        DYN_UPDATE_FORWARD,
        DYN_UPDATE_RESPONSE_IN,
        INTERNAL_LOOKUP_CNAME,
        INTERNAL_LOOKUP_ADDITIONAL,
        RRL_TO_BE_DROPPED_RESPONSE,
        RRL_TO_BE_TRUNCATED_RESPONSE,
        RRL_TO_BE_LEAKED_RESPONSE,
        RECURSE_ALIAS_FAILURE,
        DNSSEC_VALIDATION_FAILURE,
        UNKNOWN,
    }
}
