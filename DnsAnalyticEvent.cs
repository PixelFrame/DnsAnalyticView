using Microsoft.Windows.EventTracing.Events;
using System;
using System.Collections.Generic;
using System.Net;

namespace DnsAnalyticView
{
    public class DnsAnalyticEvent
    {
        public static readonly Guid Microsoft_Windows_DNSServer = new Guid("eb79061a-a566-4698-9119-3ed2807060e7");

        public DnsAnalyticEvent(IGenericEvent e)
        {
            if (e.ProviderId != Microsoft_Windows_DNSServer || e.Channel != 16) throw new ArgumentException("Not DNS Analytic event");
            if (e.Fields == null) throw new InvalidOperationException("Event decoding failed");
            Operation = e.MessageTemplate[..e.MessageTemplate.IndexOf(':')];
            Timestamp = e.Timestamp.DateTimeOffset.LocalDateTime;
            CPU = e.Processor;
            PID = e.ProcessId;
            TID = e.ThreadId;
            EventID = e.Id;
            Level = (EventLevel)e.Level;
            Keywords = e.Keyword;

            IGenericEventField value;
            if (e.Fields.TryGetValue(nameof(QNAME), out value)) QNAME = value.AsString;
            if (e.Fields.TryGetValue(nameof(QTYPE), out value)) QTYPE = (RRType)value.AsUInt32;
            if (e.Fields.TryGetValue(nameof(XID), out value)) XID = value.AsUInt32;
            if (e.Fields.TryGetValue(nameof(QXID), out value)) QXID = value.AsUInt32;
            if (e.Fields.TryGetValue(nameof(RCODE), out value)) RCODE = value.AsUInt32;
            if (e.Fields.TryGetValue(nameof(Flags), out value)) Flags = value.AsUInt32;
            if (e.Fields.TryGetValue(nameof(Secure), out value)) Secure = value.AsByte != 0;
            if (e.Fields.TryGetValue(nameof(TCP), out value)) TCP = value.AsByte != 0;
            if (e.Fields.TryGetValue(nameof(DNSSEC), out value)) DNSSEC = value.AsByte != 0;
            if (e.Fields.TryGetValue(nameof(Zone), out value)) Zone = value.AsString;
            if (e.Fields.TryGetValue(nameof(Scope), out value)) Scope = value.AsString;
            if (e.Fields.TryGetValue(nameof(PolicyName), out value)) PolicyName = value.AsString;
            if (e.Fields.TryGetValue(nameof(RecursionScope), out value)) RecursionScope = value.AsString;
            if (e.Fields.TryGetValue(nameof(CacheScope), out value)) CacheScope = value.AsString;
            if (e.Fields.TryGetValue(nameof(Reason), out value)) Reason = value.AsString;
            if (e.Fields.TryGetValue("AliasFailureReason", out value)) Reason = value.AsString;
            if (e.Fields.TryGetValue("GUID", out value)) CorrelationID = new Guid(value.AsString);
            if (e.Fields.TryGetValue("QueryGUID", out value)) CorrelationID = new Guid(value.AsString);
            if (e.Fields.TryGetValue(nameof(PacketData), out value)) PacketData = value.AsBinary;

            switch (Operation)
            {
                case "QUERY_RECEIVED":
                case "DYN_UPDATE_RECV":
                case "INTERNAL_LOOKUP_CNAME":
                case "INTERNAL_LOOKUP_ADDITIONAL":
                case "RECURSE_ALIAS_FAILURE":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["Source"].AsString, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = e.Fields["Port"].AsUInt32;
                        break;
                    }
                case "RESPONSE_SUCCESS":
                case "RESPONSE_FAILURE":
                case "RRL_TO_BE_DROPPED_RESPONSE":
                case "RRL_TO_BE_TRUNCATED_RESPONSE":
                case "RRL_TO_BE_LEAKED_RESPONSE":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["Destination"].AsString, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstPort = e.Fields["Port"].AsUInt32;
                        break;
                    }
                case "IGNORED_QUERY":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["Source"].AsString, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "RECURSE_QUERY_OUT":
                case "RECURSE_QUERY_TIMEOUT":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["Destination"].AsString, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = e.Fields["Port"].AsUInt32;
                        break;
                    }
                case "RECURSE_RESPONSE_IN":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["Source"].AsString, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = e.Fields["Port"].AsUInt32;
                        break;
                    }
                case "IXFR_REQ_OUT":
                case "AXFR_REQ_OUT":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["Source"].AsString, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "IXFR_REQ_RECV":
                case "AXFR_REQ_RECV":
                case "XFR_NOTIFY_RECV":
                case "XFR_NOTIFY_ACK_IN":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["Source"].AsString, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "IXFR_RESP_OUT":
                case "AXFR_RESP_OUT":
                case "XFR_NOTIFY_OUT":
                case "XFR_NOTIFY_ACK_OUT":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["Destination"].AsString, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "IXFR_RESP_RECV":
                case "AXFR_RESP_RECV":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["Destination"].AsString, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
                case "DYN_UPDATE_FORWARD":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["ForwardInterfaceIP"].AsString, out var ForwardInterfaceIPAddr) ? ForwardInterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["Destination"].AsString, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "DYN_UPDATE_RESPONSE_IN":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["Source"].AsString, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
                case "DYN_UPDATE_RESPONSE":
                    {
                        SrcAddr = IPAddress.TryParse(e.Fields["InterfaceIP"].AsString, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.Fields["Destination"].AsString, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
            }
        }
        public string Operation { get; set; }
        public DateTime Timestamp { get; set; }
        public int CPU { get; set; }
        public int PID { get; set; }
        public int TID { get; set; }
        public int EventID { get; set; }
        public long Keywords { get; set; }
        public EventLevel Level { get; set; }
        public string QNAME { get; set; } = string.Empty;
        public RRType QTYPE { get; set; } = 0;
        public uint XID { get; set; } = 0;
        public uint QXID { get; set; } = 0;
        public uint RCODE { get; set; } = 0;
        public uint Flags { get; set; } = 0;
        public bool TCP { get; set; } = false;
        public bool DNSSEC { get; set; } = false;
        public bool Secure { get; set; } = false;
        public IPAddress SrcAddr { get; set; } = IPAddress.Any;
        public IPAddress DstAddr { get; set; } = IPAddress.Any;
        public uint SrcPort { get; set; } = 53;
        public uint DstPort { get; set; } = 53;
        public string Zone { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty;
        public string PolicyName { get; set; } = string.Empty;
        public string RecursionScope { get; set; } = string.Empty;
        public string CacheScope { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public Guid CorrelationID { get; set; } = Guid.Empty;
        public IReadOnlyList<byte> PacketData { get; set; } = Array.Empty<byte>();
    }

    public enum EventLevel
    {
        Error = 2,
        Warning = 3,
        Informational = 4,
    }

    public enum RRType
    {
        Reserved0 = 0,
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        X25 = 19,
        ISDN = 20,
        RT = 21,
        NSAP = 22,
        NSAP_PTR = 23,
        SIG = 24,
        KEY = 25,
        PX = 26,
        GPOS = 27,
        AAAA = 28,
        LOC = 29,
        NXT = 30,
        EID = 31,
        NIMLOC = 32,
        SRV = 33,
        ATMA = 34,
        NAPTR = 35,
        KX = 36,
        CERT = 37,
        A6 = 38,
        DNAME = 39,
        SINK = 40,
        OPT = 41,
        APL = 42,
        DS = 43,
        SSHFP = 44,
        IPSECKEY = 45,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        SMIMEA = 53,
        HIP = 55,
        NINFO = 56,
        RKEY = 57,
        TALINK = 58,
        CDS = 59,
        CDNSKEY = 60,
        OPENPGPKEY = 61,
        CSYNC = 62,
        ZONEMD = 63,
        SVCB = 64,
        HTTPS = 65,
        SPF = 99,
        UINFO = 100,
        UID = 101,
        GID = 102,
        UNSPEC = 103,
        NID = 104,
        L32 = 105,
        L64 = 106,
        LP = 107,
        EUI48 = 108,
        EUI64 = 109,
        NXNAME = 128,
        TKEY = 249,
        TSIG = 250,
        IXFR = 251,
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        Wildcard = 255,
        URI = 256,
        CAA = 257,
        AVC = 258,
        DOA = 259,
        AMTRELAY = 260,
        RESINFO = 261,
        WALLET = 262,
        TA = 32768,
        DLV = 32769,
        Reserved = 65535
    }
}
