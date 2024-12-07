using Microsoft.Performance.SDK.Extensibility.SourceParsing;
using Microsoft.Performance.SDK.Processing;
using System;

namespace DnsAnalyticView
{
    public class DnsAnalyticDataProcessor : CustomDataProcessorWithSourceParser<DnsAnalyticEvent, object, Guid>
    {
        internal DnsAnalyticDataProcessor(
            ISourceParser<DnsAnalyticEvent, object, Guid> sourceParser,
            ProcessorOptions options,
            IApplicationEnvironment applicationEnvironment,
            IProcessorEnvironment processorEnvironment)
            : base(sourceParser, options, applicationEnvironment, processorEnvironment)
        {
        }
    }
}
