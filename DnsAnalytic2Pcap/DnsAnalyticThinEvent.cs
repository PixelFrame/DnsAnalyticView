using DnsAnalyticView;
using Microsoft.Diagnostics.Tracing;
using System.Net;

namespace DnsAnalytic2Pcap
{
    public class DnsAnalyticThinEvent
    {
        public static readonly Guid Microsoft_Windows_DNSServer = new("eb79061a-a566-4698-9119-3ed2807060e7");

        internal static DateTime TraceStartTime = DateTime.MinValue;

        public static readonly Dictionary<int, DnsAnalyticOperation> Operations = new()
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

        public DnsAnalyticThinEvent(TraceEvent e)
        {
            if (e.ProviderGuid != Microsoft_Windows_DNSServer || e.Channel != (TraceEventChannel)16) throw new ArgumentException("Not DNS Analytic event");
            Operation = Operations.TryGetValue((int)e.ID, out var op) ? op
                : DnsAnalyticOperation.UNKNOWN;
            Timestamp = e.TimeStamp;

            TCP = e.BooleanPayloadByName(nameof(TCP));

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

            if (e.PayloadNames.Contains(nameof(PacketData))) PacketData = (byte[])e.PayloadByName(nameof(PacketData));
        }
        public DnsAnalyticOperation Operation { get; set; }
        public DateTime Timestamp { get; set; }
        public bool TCP { get; set; } = false;
        public IPAddress SrcAddr { get; set; } = IPAddress.Any;
        public IPAddress DstAddr { get; set; } = IPAddress.Any;
        public uint SrcPort { get; set; } = 53;
        public uint DstPort { get; set; } = 53;
        public byte[] PacketData { get; set; } = [];
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
