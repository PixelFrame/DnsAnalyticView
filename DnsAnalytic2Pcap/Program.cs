﻿using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Extensions.Logging;
using DnsAnalyticView;

namespace DnsAnalytic2Pcap
{
    internal class Program
    {
        private static readonly int[] ShouldNotConvert =
            [262, 279, 280, 281, 282, 283, 288, 291];

        static void Main(string[] args)
        {
            using var source = new ETWTraceEventSource(args[0]);
            using var writer = new DnsAnalyticPacketWriter(args[1]);
            using var manifestStream = new MemoryStream(System.Text.Encoding.ASCII.GetBytes(Manifests._10_0_26100_1457));
            var manifest = new ProviderManifest(manifestStream);

            source.Dynamic.AddDynamicProvider(manifest);
            source.Dynamic.AddCallbackForProviderEvent("Microsoft-Windows-DNSServer", null, delegate (TraceEvent e)
            {
                try
                {
                    var id = (int)e.ID;
                    if (id < 256 || id > 291 || ShouldNotConvert.Contains(id))
                    {
                        Console.WriteLine("Skipping event {0}", DnsAnalyticThinEvent.Operations.TryGetValue(id, out var op) ? op : id);
                        return;
                    }
                    var evt = new DnsAnalyticThinEvent(e, source.SessionStartTime.Ticks);
                    writer.ConstructPacket(evt);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error occured during parsing event with ID {0}: {1}", e.ID, ex.Message);
                }
            });
            source.Process();
            if (source.EventsLost > 0) { Console.WriteLine("[WARNING] {0} events lost in trace", source.EventsLost); }
            if (source.SessionEndTime < DateTime.UnixEpoch)
            {
                Console.WriteLine("[WARNING] Trace was not properly stopped");
            }
            Console.WriteLine("Done parsing events");
        }
    }
}
