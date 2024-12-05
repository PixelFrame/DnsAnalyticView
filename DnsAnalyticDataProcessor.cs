using Microsoft.Performance.SDK.Processing;
using Microsoft.Windows.EventTracing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DnsAnalyticView
{
    public sealed class DnsAnalyticDataProcessor
        : CustomDataProcessor
    {
        private readonly string[] filePaths;
        private DataSourceInfo dataSourceInfo = new DataSourceInfo(0, 0, DateTime.UtcNow);
        private Dictionary<string, List<DnsAnalyticEvent>> events = new Dictionary<string, List<DnsAnalyticEvent>>();
        private DateTime startTime;

        public DnsAnalyticDataProcessor(
           string[] filePaths,
           ProcessorOptions options,
           IApplicationEnvironment applicationEnvironment,
           IProcessorEnvironment processorEnvironment)
            : base(options, applicationEnvironment, processorEnvironment)
        {
            this.filePaths = filePaths;
        }

        public override DataSourceInfo GetDataSourceInfo()
        {
            return dataSourceInfo;
        }

        protected override Task ProcessAsyncCore(
           IProgress<int> progress,
           CancellationToken cancellationToken)
        {
            double currentFile = 0;
            var startTime = DateTime.MaxValue;
            var endTime = DateTime.MinValue;
            foreach (var path in filePaths)
            {
                using var trace = TraceProcessor.Create(path, new TraceProcessorSettings() { AllowLostEvents = true });
                var pendingProcessData = trace.UseGenericEvents(DnsAnalyticEvent.Microsoft_Windows_DNSServer);
                trace.Process();
                var eventData = pendingProcessData.Result;

                var newEvents = new List<DnsAnalyticEvent>();
                foreach (var e in eventData.Events)
                {
                    try
                    {
                        var evt = new DnsAnalyticEvent(e);
                        newEvents.Add(evt);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error("Error occured during parsing event with ID {0}: {1}", e.Id, ex.Message);
                    }
                }
                if (newEvents.Count == 0)
                {
                    Logger.Error("No event processed, either decoding failed or the log does not contain the provider");
                    continue;
                }
                else
                {
                    Logger.Info("Processed {0} events from {1}", eventData.Events.Count, path);
                }
                if (newEvents[0].Timestamp < startTime) { startTime = newEvents[0].Timestamp; }
                if (newEvents.Last().Timestamp > endTime) { endTime = newEvents.Last().Timestamp; }
                events.Add(path, newEvents);
                currentFile++;
                progress.Report((int)(currentFile / filePaths.Length * 100));
            }
            this.startTime = startTime;
            dataSourceInfo = new DataSourceInfo(0, (endTime - startTime).Ticks * 100, startTime.ToUniversalTime());
            progress.Report(100);
            return Task.CompletedTask;
        }

        protected override void BuildTableCore(
            TableDescriptor tableDescriptor,
            ITableBuilder tableBuilder)
        {
            var table = new DnsAnalyticTable(events, startTime);
            table.Build(tableBuilder);
        }
    }
}
