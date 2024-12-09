using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Extensibility;
using Microsoft.Performance.SDK.Processing;
using System;
using System.Collections.Generic;

namespace DnsAnalyticView
{
    [Table]
    public sealed class DnsAnalyticTable
    {
        public static TableDescriptor TableDescriptor => new TableDescriptor(
            Guid.Parse("{BA351884-2217-4199-A8BB-6C119BEFFE8D}"),
            "DNS Analytic",
            "DNS Server Analytical Events",
            "DNS Server",
            requiredDataCookers: new List<DataCookerPath> { DnsAnalyticEventCooker.CookerPath });

        #region Columns
        private static readonly ColumnConfiguration QNAMEColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA0-39F1-4A27-9BB6-D7622FA08267}"), "QNAME", "Query Name"),
            new UIHints { Width = 120 });

        private static readonly ColumnConfiguration QTYPEColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA1-39F1-4A27-9BB6-D7622FA08267}"), "QTYPE", "Query Type"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration XIDColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA2-39F1-4A27-9BB6-D7622FA08267}"), "XID", "Transaction ID"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration QXIDColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA3-39F1-4A27-9BB6-D7622FA08267}"), "QXID", "Query Transacation ID"),
            new UIHints { Width = 40, IsVisible = false });

        private static readonly ColumnConfiguration RCODEColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA4-39F1-4A27-9BB6-D7622FA08267}"), "RCODE", "DNS RCODE"),
            new UIHints { Width = 80 });

        private static readonly ColumnConfiguration RDColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA5-39F1-4A27-9BB6-D7622FA08267}"), "RD", "Recursion Desired"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration AAColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA6-39F1-4A27-9BB6-D7622FA08267}"), "AA", "Authorized Answer"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration ADColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA7-39F1-4A27-9BB6-D7622FA08267}"), "AD", "Authenticated"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration FlagsColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA8-39F1-4A27-9BB6-D7622FA08267}"), "Flags", "DNS Flags"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration FlagsAltColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FACA8-39F1-4A27-9BB6-D7622FA08267}"), "Flags (Interpreted)", "Interpreted DNS Flags"),
            new UIHints { Width = 100, IsVisible = false });

        private static readonly ColumnConfiguration DNSSECColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABA9-39F1-4A27-9BB6-D7622FA08267}"), "DNSSEC", "Is DNSSEC"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration SecureColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABB0-39F1-4A27-9BB6-D7622FA08267}"), "Secure", "Is Secure Update"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration ReasonColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABB1-39F1-4A27-9BB6-D7622FA08267}"), "Reason", "Failure Reason"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration EDNSUdpPayloadSizeColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABB2-39F1-4A27-9BB6-D7622FA08267}"), "EDNSUdpPayloadSize", "EDNS UDP Payload Size"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration SourceColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD0-39F1-4A27-9BB6-D7622FA08267}"), "Source", "Packet Source"),
            new UIHints { Width = 100 });

        private static readonly ColumnConfiguration DestinationColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD1-39F1-4A27-9BB6-D7622FA08267}"), "Destination", "Packet Destination"),
            new UIHints { Width = 100 });

        private static readonly ColumnConfiguration TCPColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD2-39F1-4A27-9BB6-D7622FA08267}"), "TCP", "Is TCP Packet"),
            new UIHints { Width = 40, IsVisible = false });

        private static readonly ColumnConfiguration SrcAddrColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD3-39F1-4A27-9BB6-D7622FA08267}"), "SrcAddr", "Packet Source Address"),
            new UIHints { Width = 80, IsVisible = false });

        private static readonly ColumnConfiguration SrcPortColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD4-39F1-4A27-9BB6-D7622FA08267}"), "SrcPort", "Packet Source Port"),
            new UIHints { Width = 40, IsVisible = false });

        private static readonly ColumnConfiguration DstAddrColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD5-39F1-4A27-9BB6-D7622FA08267}"), "DstAddr", "Packet Destination Address"),
            new UIHints { Width = 80, IsVisible = false });

        private static readonly ColumnConfiguration DstPortColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD6-39F1-4A27-9BB6-D7622FA08267}"), "DstPort", "Packet Destination Port"),
            new UIHints { Width = 40, IsVisible = false });

        private static readonly ColumnConfiguration RemoteAddrColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABD7-39F1-4A27-9BB6-D7622FA08267}"), "Remote Address", "Packet Remote Address"),
            new UIHints { Width = 80 });

        private static readonly ColumnConfiguration ZoneColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABE0-39F1-4A27-9BB6-D7622FA08267}"), "Zone", "Matched Zone"),
            new UIHints { Width = 120 });

        private static readonly ColumnConfiguration ScopeColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABE1-39F1-4A27-9BB6-D7622FA08267}"), "Scope", "Matched Scope"),
            new UIHints { Width = 80 });

        private static readonly ColumnConfiguration PolicyNameColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABE2-39F1-4A27-9BB6-D7622FA08267}"), "PolicyName", "Matched DNS Policy Name"),
            new UIHints { Width = 80 });

        private static readonly ColumnConfiguration RecursionScopeColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABE3-39F1-4A27-9BB6-D7622FA08267}"), "RecursionScope", "Matched Recursion Scope"),
            new UIHints { Width = 80 });

        private static readonly ColumnConfiguration CacheScopeColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABE4-39F1-4A27-9BB6-D7622FA08267}"), "CacheScope", "Matched Cache Scope"),
            new UIHints { Width = 80 });

        private static readonly ColumnConfiguration RecursionDepthColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABE5-39F1-4A27-9BB6-D7622FA08267}"), "RecursionDepth", "Recursion Depth"),
            new UIHints { Width = 40, IsVisible = false });

        private static readonly ColumnConfiguration ElapsedTimeColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABE6-39F1-4A27-9BB6-D7622FA08267}"), "ElapsedTime", "Elapsed Time"),
            new UIHints { Width = 80, AggregationMode = AggregationMode.Max });

        private static readonly ColumnConfiguration CorrelationIDColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB90-39F1-4A27-9BB6-D7622FA08267}"), "CorrelationID", "GUID to group a query"),
            new UIHints { Width = 160 });

        private static readonly ColumnConfiguration OperationColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB91-39F1-4A27-9BB6-D7622FA08267}"), "Operation", "Server Operation"),
            new UIHints { Width = 120 });

        private static readonly ColumnConfiguration TimeColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB92-39F1-4A27-9BB6-D7622FA08267}"), "Time", "Event Time"),
            new UIHints { Width = 180, AggregationMode = AggregationMode.Min });

        private static readonly ColumnConfiguration CPUColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB93-39F1-4A27-9BB6-D7622FA08267}"), "CPU", "CPU Core where the event was fired"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration PIDColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB94-39F1-4A27-9BB6-D7622FA08267}"), "PID", "Process ID"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration TIDColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB95-39F1-4A27-9BB6-D7622FA08267}"), "TID", "Thread ID"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration EventIDColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB96-39F1-4A27-9BB6-D7622FA08267}"), "EventID", "Event ID"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration KeywordsColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB97-39F1-4A27-9BB6-D7622FA08267}"), "Keywords", "Event Keywords"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration LevelColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FAB98-39F1-4A27-9BB6-D7622FA08267}"), "Level", "Event Level"),
            new UIHints { Width = 40 });

        private static readonly ColumnConfiguration RelativeTimeColumn = new ColumnConfiguration(
            new ColumnMetadata(new Guid("{727FABFF-39F1-4A27-9BB6-D7622FA08267}"), "RelativeTime", "Relative Time"),
            new UIHints { Width = 100, AggregationMode = AggregationMode.Min });

        #endregion

        public static void BuildTable(ITableBuilder tableBuilder, IDataExtensionRetrieval tableData)
        {
            var events = tableData.QueryOutput<List<DnsAnalyticEvent>>(new DataOutputPath(DnsAnalyticEventCooker.CookerPath, "Events"));

            var baseProjection = Projection.Index(events);

            var cpuProjection = baseProjection.Compose(x => x.CPU);
            var pidProjection = baseProjection.Compose(x => x.PID);
            var tidProjection = baseProjection.Compose(x => x.TID);
            var eventIdProjection = baseProjection.Compose(x => x.EventID);
            var keywordsProjection = baseProjection.Compose(x => x.Keywords);
            var levelProjection = baseProjection.Compose(x => x.Level);
            var qnameProjection = baseProjection.Compose(x => x.QNAME);
            var qtypeProjection = baseProjection.Compose(x => x.QTYPE);
            var xidProjection = baseProjection.Compose(x => x.XID.ToString("X4"));
            var qxidProjection = baseProjection.Compose(x => x.QXID.ToString("X4"));
            var rcodeProjection = baseProjection.Compose(x => x.RCODE);
            var reasonProjection = baseProjection.Compose(x => x.Reason);
            var ednsUdpPayloadSizeProjection = baseProjection.Compose(x => x.EDNSUdpPayloadSize);
            var flagsProjection = baseProjection.Compose(x => x.Flags.ToString("X4"));
            var flagsAltProjection = baseProjection.Compose(x => DnsUtilities.FlagsToString(x.Flags));
            var rdProjection = baseProjection.Compose(x => x.RD);
            var aaProjection = baseProjection.Compose(x => x.AA);
            var adProjection = baseProjection.Compose(x => x.AD);
            var dnssecProjection = baseProjection.Compose(x => x.DNSSEC);
            var secureProjection = baseProjection.Compose(x => x.Secure);
            var sourceProjection = baseProjection.Compose(x => $"{x.SrcAddr}:{x.SrcPort}");
            var destinationProjection = baseProjection.Compose(x => $"{x.DstAddr}:{x.DstPort}");
            var srcAddrProjection = baseProjection.Compose(x => x.SrcAddr.ToString());          // ToString is necessary for grouping, appears IPAddress does not have certain interface implemented
            var srcPortProjection = baseProjection.Compose(x => x.SrcPort);
            var dstAddrProjection = baseProjection.Compose(x => x.DstAddr.ToString());
            var dstPortProjection = baseProjection.Compose(x => x.DstPort);
            var remoteAddrProjection = baseProjection.Compose(x => x.RemoteAddr.ToString());
            var tcpProjection = baseProjection.Compose(x => x.TCP);
            var zoneProjection = baseProjection.Compose(x => x.Zone);
            var scopeProjection = baseProjection.Compose(x => x.Scope);
            var policyNameProjection = baseProjection.Compose(x => x.PolicyName);
            var recursionScopeProjection = baseProjection.Compose(x => x.RecursionScope);
            var cacheScopeProjection = baseProjection.Compose(x => x.CacheScope);
            var recursionDepthProjection = baseProjection.Compose(x => x.RecursionDepth);
            var elapsedTimeProjection = baseProjection.Compose(x => TimestampDelta.FromMilliseconds(x.ElapsedTime));    // After testing with several traces, millisecond should be the correct unit.
            var correlationIdProjection = baseProjection.Compose(x => x.CorrelationID);
            var operationProjection = baseProjection.Compose(x => x.Operation);
            var timeProjection = baseProjection.Compose(x => x.Timestamp);
            var relativeTimeProjection = baseProjection.Compose(x => x.RelativeTime);

            var byCorrelationIdConfig = new TableConfiguration("By CorrelationID")
            {
                Columns = new[]
                {
                    CorrelationIDColumn,
                    TableConfiguration.PivotColumn,
                    OperationColumn,
                    QNAMEColumn,
                    QTYPEColumn,
                    XIDColumn,
                    QXIDColumn,
                    SourceColumn,
                    DestinationColumn,
                    SrcAddrColumn,
                    SrcPortColumn,
                    DstAddrColumn,
                    DstPortColumn,
                    TCPColumn,
                    RCODEColumn,
                    FlagsColumn,
                    FlagsAltColumn,
                    DNSSECColumn,
                    SecureColumn,
                    ZoneColumn,
                    ScopeColumn,
                    PolicyNameColumn,
                    RecursionScopeColumn,
                    CacheScopeColumn,
                    ElapsedTimeColumn,
                    TimeColumn,
                    TableConfiguration.GraphColumn,
                    RelativeTimeColumn,
                },
            };

            var byQNameConfig = new TableConfiguration("By QNAME")
            {
                Columns = new[]
                {
                    QNAMEColumn,
                    TableConfiguration.PivotColumn,
                    CorrelationIDColumn,
                    OperationColumn,
                    QTYPEColumn,
                    XIDColumn,
                    QXIDColumn,
                    SourceColumn,
                    DestinationColumn,
                    SrcAddrColumn,
                    SrcPortColumn,
                    DstAddrColumn,
                    DstPortColumn,
                    TCPColumn,
                    RCODEColumn,
                    FlagsColumn,
                    FlagsAltColumn,
                    DNSSECColumn,
                    SecureColumn,
                    ZoneColumn,
                    ScopeColumn,
                    PolicyNameColumn,
                    RecursionScopeColumn,
                    CacheScopeColumn,
                    ElapsedTimeColumn,
                    TimeColumn,
                    TableConfiguration.GraphColumn,
                    RelativeTimeColumn,
                },
            };

            var byRemoteAddrConfig = new TableConfiguration("By Remote Address")
            {
                Columns = new[]
                {
                    RemoteAddrColumn,
                    TableConfiguration.PivotColumn,
                    QNAMEColumn,
                    CorrelationIDColumn,
                    OperationColumn,
                    QTYPEColumn,
                    XIDColumn,
                    QXIDColumn,
                    SourceColumn,
                    DestinationColumn,
                    SrcAddrColumn,
                    SrcPortColumn,
                    DstAddrColumn,
                    DstPortColumn,
                    TCPColumn,
                    RCODEColumn,
                    FlagsColumn,
                    FlagsAltColumn,
                    DNSSECColumn,
                    SecureColumn,
                    ZoneColumn,
                    ScopeColumn,
                    PolicyNameColumn,
                    RecursionScopeColumn,
                    CacheScopeColumn,
                    ElapsedTimeColumn,
                    TimeColumn,
                    TableConfiguration.GraphColumn,
                    RelativeTimeColumn,
                },
            };

            byCorrelationIdConfig.AddColumnRole(ColumnRole.EndTime, RelativeTimeColumn);
            byCorrelationIdConfig.AddColumnRole(ColumnRole.Duration, ElapsedTimeColumn);
            byQNameConfig.AddColumnRole(ColumnRole.EndTime, RelativeTimeColumn);
            byQNameConfig.AddColumnRole(ColumnRole.Duration, ElapsedTimeColumn);
            byRemoteAddrConfig.AddColumnRole(ColumnRole.EndTime, RelativeTimeColumn);
            byRemoteAddrConfig.AddColumnRole(ColumnRole.Duration, ElapsedTimeColumn);

            tableBuilder
                .AddTableConfiguration(byCorrelationIdConfig)
                .AddTableConfiguration(byQNameConfig)
                .AddTableConfiguration(byRemoteAddrConfig)
                .SetDefaultTableConfiguration(byCorrelationIdConfig)
                .SetRowCount(events.Count)
                .AddColumn(CorrelationIDColumn, correlationIdProjection)
                .AddColumn(OperationColumn, operationProjection)
                .AddColumn(QNAMEColumn, qnameProjection)
                .AddColumn(QTYPEColumn, qtypeProjection)
                .AddColumn(XIDColumn, xidProjection)
                .AddColumn(QXIDColumn, qxidProjection)
                .AddColumn(SourceColumn, sourceProjection)
                .AddColumn(DestinationColumn, destinationProjection)
                .AddColumn(SrcAddrColumn, srcAddrProjection)
                .AddColumn(DstAddrColumn, dstAddrProjection)
                .AddColumn(RemoteAddrColumn, remoteAddrProjection)
                .AddColumn(SrcPortColumn, srcPortProjection)
                .AddColumn(DstPortColumn, dstPortProjection)
                .AddColumn(TCPColumn, tcpProjection)
                .AddColumn(RCODEColumn, rcodeProjection)
                .AddColumn(ReasonColumn, reasonProjection)
                .AddColumn(EDNSUdpPayloadSizeColumn, ednsUdpPayloadSizeProjection)
                .AddColumn(FlagsColumn, flagsProjection)
                .AddColumn(FlagsAltColumn, flagsAltProjection)
                // Column variants not available yet
                //.AddColumnWithVariants(FlagsColumn, flagsProjection, builder =>
                //{
                //    return builder.WithModes("HEX")
                //        .WithMode(FlagsAltColumn, "Interpreted", flagsAltProjection);
                //})
                .AddColumn(RDColumn, rdProjection)
                .AddColumn(AAColumn, aaProjection)
                .AddColumn(ADColumn, adProjection)
                .AddColumn(DNSSECColumn, dnssecProjection)
                .AddColumn(SecureColumn, secureProjection)
                .AddColumn(ZoneColumn, zoneProjection)
                .AddColumn(ScopeColumn, scopeProjection)
                .AddColumn(PolicyNameColumn, policyNameProjection)
                .AddColumn(RecursionScopeColumn, recursionScopeProjection)
                .AddColumn(CacheScopeColumn, cacheScopeProjection)
                .AddColumn(RecursionDepthColumn, recursionDepthProjection)
                .AddColumn(ElapsedTimeColumn, elapsedTimeProjection)
                .AddColumn(TimeColumn, timeProjection)
                .AddColumn(CPUColumn, cpuProjection)
                .AddColumn(PIDColumn, pidProjection)
                .AddColumn(TIDColumn, tidProjection)
                .AddColumn(EventIDColumn, eventIdProjection)
                .AddColumn(KeywordsColumn, keywordsProjection)
                .AddColumn(LevelColumn, levelProjection)
                .AddColumn(RelativeTimeColumn, relativeTimeProjection);
        }
    }
}
