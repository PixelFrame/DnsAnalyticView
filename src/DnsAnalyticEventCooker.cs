using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Extensibility.DataCooking;
using Microsoft.Performance.SDK.Extensibility.DataCooking.SourceDataCooking;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace DnsAnalyticView
{
    public sealed class DnsAnalyticEventCooker : SourceDataCooker<DnsAnalyticEvent, object, Guid>
    {
        public static readonly DataCookerPath CookerPath = DataCookerPath.ForSource(DnsAnalyticParser.SourceId, Identifier);
        public const string Identifier = "DnsAnalyticCooker";
        public override DataCookerPath Path => CookerPath;
        public override string Description => "DnsAnalytic Event Cooker";

        public DnsAnalyticEventCooker() : base(CookerPath)
        {
            Events = new List<DnsAnalyticEvent>();
        }

        public override ReadOnlyHashSet<Guid> DataKeys => new ReadOnlyHashSet<Guid>(new HashSet<Guid>() { });

        public override SourceDataCookerOptions Options => SourceDataCookerOptions.ReceiveAllDataElements;

        public override IReadOnlyDictionary<DataCookerPath, DataCookerDependencyType> DependencyTypes =>
            new Dictionary<DataCookerPath, DataCookerDependencyType>();

        public override IReadOnlyCollection<DataCookerPath> RequiredDataCookers => new HashSet<DataCookerPath>();

        public override DataProductionStrategy DataProductionStrategy { get; }

        [DataOutput]
        public List<DnsAnalyticEvent> Events { get; }

        public override DataProcessingResult CookDataElement(DnsAnalyticEvent data, object context, CancellationToken cancellationToken)
        {
            Debug.Assert(!(data is null));
            Events.Add(data);
            return DataProcessingResult.Processed;
        }
    }
}
