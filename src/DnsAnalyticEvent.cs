using Microsoft.Diagnostics.Tracing;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace DnsAnalyticView
{
    public class DnsAnalyticEvent : IKeyedDataType<Guid>, IComparable<Guid>
    {
        public static readonly Guid Microsoft_Windows_DNSServer = new Guid("eb79061a-a566-4698-9119-3ed2807060e7");

        internal static DateTime TraceStartTime = DateTime.MinValue;

        public DnsAnalyticEvent(TraceEvent e, long startTime, bool LoadPacketData = false)
        {
            if (e.ProviderGuid != Microsoft_Windows_DNSServer || e.Channel != (TraceEventChannel)16) throw new ArgumentException("Not DNS Analytic event");
            Operation = e.FormattedMessage[..e.FormattedMessage.IndexOf(':')];
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
                case "QUERY_RECEIVED":
                case "DYN_UPDATE_RECV":
                case "INTERNAL_LOOKUP_CNAME":
                case "INTERNAL_LOOKUP_ADDITIONAL":
                case "RECURSE_ALIAS_FAILURE":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case "RESPONSE_SUCCESS":
                case "RESPONSE_FAILURE":
                case "RRL_TO_BE_DROPPED_RESPONSE":
                case "RRL_TO_BE_TRUNCATED_RESPONSE":
                case "RRL_TO_BE_LEAKED_RESPONSE":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case "IGNORED_QUERY":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "RECURSE_QUERY_OUT":
                case "RECURSE_QUERY_TIMEOUT":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case "RECURSE_RESPONSE_IN":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = e.UIntPayloadByName("Port");
                        break;
                    }
                case "IXFR_REQ_OUT":
                case "AXFR_REQ_OUT":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "IXFR_REQ_RECV":
                case "AXFR_REQ_RECV":
                case "XFR_NOTIFY_RECV":
                case "XFR_NOTIFY_ACK_IN":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "IXFR_RESP_OUT":
                case "AXFR_RESP_OUT":
                //case "XFR_NOTIFY_OUT":
                case "XFR_NOTIFY_ACK_OUT":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                // Well, in Windows Server 2025 manifest, XFR_NOTIFY_OUT uses "Source" field as destination address
                case "XFR_NOTIFY_OUT":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "IXFR_RESP_RECV":
                case "AXFR_RESP_RECV":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
                case "DYN_UPDATE_FORWARD":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("ForwardInterfaceIP") as string, out var ForwardInterfaceIPAddr) ? ForwardInterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        SrcPort = 0;
                        break;
                    }
                case "DYN_UPDATE_RESPONSE_IN":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("Source") as string, out var SourceAddr) ? SourceAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
                case "DYN_UPDATE_RESPONSE":
                    {
                        SrcAddr = IPAddress.TryParse(e.PayloadByName("InterfaceIP") as string, out var InterfaceIPAddr) ? InterfaceIPAddr : IPAddress.Any;
                        DstAddr = IPAddress.TryParse(e.PayloadByName("Destination") as string, out var DestinationAddr) ? DestinationAddr : IPAddress.Any;
                        DstPort = 0;
                        break;
                    }
            }

            if (LoadPacketData && e.PayloadNames.Contains(nameof(PacketData))) PacketData = (byte[])e.PayloadByName(nameof(PacketData));
        }
        public string Operation { get; set; }
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
        public IReadOnlyList<byte> PacketData { get; set; } = Array.Empty<byte>();
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

    public enum RRType
    {
        NotAvailable = 0,
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

    public enum RCODE
    {
        NoError = 0,
        FormErr = 1,
        ServFail = 2,
        NXDomain = 3,
        NotImp = 4,
        Refused = 5,
        YXDomain = 6,
        YXRRSet = 7,
        NXRRSet = 8,
        NotAuth = 9,
        NotZone = 10,
        DSOTYPENI = 11,
        BADSIG = 16,
        BADKEY = 17,
        BADTIME = 18,
        BADMODE = 19,
        BADNAME = 20,
        BADALG = 21,
        BADTRUNC = 22,
        BADCOOKIE = 23,
        Reserved = 65535
    }
}
