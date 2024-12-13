using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Performance.SDK.Extensibility.SourceParsing;
using Microsoft.Performance.SDK.Processing;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using ILogger = Microsoft.Performance.SDK.Processing.ILogger;

namespace DnsAnalyticView
{
    public sealed class DnsAnalyticParser : SourceParser<DnsAnalyticEvent, object, Guid>
    {
        public const string SourceId = "DnsAnalyticParser";
        public override string Id => SourceId;

        private DataSourceInfo? info;
        public override DataSourceInfo DataSourceInfo => info ?? throw new InvalidOperationException("Data Source has not been processed");

        private readonly IEnumerable<string> filePaths;

        private static readonly int[] NotForPacket =
            [262, 279, 280, 281, 282, 283, 288, 291];

        public DnsAnalyticParser(IEnumerable<string> filePaths)
        {
            this.filePaths = filePaths;
        }

        public override void ProcessSource(ISourceDataProcessor<DnsAnalyticEvent, object, Guid> dataProcessor, ILogger logger, IProgress<int> progress, CancellationToken cancellationToken)
        {
            using var source = new ETWTraceEventSource(filePaths);
            var manifestStream = new MemoryStream(System.Text.Encoding.ASCII.GetBytes(Manifests._10_0_26100_1457));
            var manifest = new ProviderManifest(manifestStream);
            var lastEventTime = DateTime.MinValue;

            source.Dynamic.AddDynamicProvider(manifest);
            source.Dynamic.AddCallbackForProviderEvent("Microsoft-Windows-DNSServer", null, delegate (TraceEvent e)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    source.StopProcessing();
                    return;
                }
                try
                {
                    var evt = new DnsAnalyticEvent(e, source.SessionStartTime.Ticks, !NotForPacket.Contains((int)e.ID));
                    dataProcessor.ProcessDataElement(evt, this, cancellationToken);
                    lastEventTime = e.TimeStamp;
                }
                catch (Exception ex)
                {
                    logger.Error("Error occured during parsing event with ID {0}: {1}", e.ID, ex.Message);
                }
                progress.Report((int)(e.TimeStampRelativeMSec / source.SessionEndTimeRelativeMSec * 100));
            });
            source.Process();
            if (source.EventsLost > 0) { logger.Warn("[WARNING] {0} events lost in trace", source.EventsLost); }
            if (source.SessionEndTime < DateTime.UnixEpoch)
            {
                logger.Warn("[WARNING] Trace was not properly stopped");
                info = new DataSourceInfo(0, (lastEventTime.Ticks - source.SessionStartTime.Ticks) * 100, source.SessionStartTime.ToUniversalTime());
            }
            logger.Info("Done parsing events");

            info ??= new DataSourceInfo(0, (source.SessionEndTime.Ticks - source.SessionStartTime.Ticks) * 100, source.SessionStartTime.ToUniversalTime());  // Using session time should be fine for a properly stopped trace, but if an ETL file is copied without stopping this will be a problem
        }
    }
}
