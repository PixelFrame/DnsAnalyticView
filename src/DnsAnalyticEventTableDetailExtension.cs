using KzA.DNS;
using KzA.DNS.Packet;
using Microsoft.Performance.SDK.Processing;
using System;
using System.Collections.Generic;
using System.Text;

namespace DnsAnalyticView
{
    internal static class DnsAnalyticEventTableDetailExtension
    {
        public static List<TableRowDetailEntry> ToRowDetail(this DnsAnalyticEvent evt)
        {
            var result = new List<TableRowDetailEntry>();
            if (evt.PacketData.Length == 0) return result;

            try
            {
                var msg = DnsMessage.Parse(evt.PacketData, false);
                result.Add(new TableRowDetailEntry("XID", msg.Header.TransactionID.ToString("X4")));
                var flagsEntry = new TableRowDetailEntry("Flags", $"{msg.Header.Flags:X4} {DnsUtilities.FlagsToString(msg.Header.Flags)}");
                flagsEntry.AddChildDetailsInfo(new("QR", msg.Header.HeaderFlags.HasFlag(HeaderFlags.QR) ? "1 - Response" : "0 - Request"));
                flagsEntry.AddChildDetailsInfo(new("OpCode", msg.Header.OpCode.ToString()));
                flagsEntry.AddChildDetailsInfo(new("AA", msg.Header.HeaderFlags.HasFlag(HeaderFlags.AA) ? "1 - Authoritative" : "0 - Not Authoritative"));
                flagsEntry.AddChildDetailsInfo(new("TC", msg.Header.HeaderFlags.HasFlag(HeaderFlags.TC) ? "1 - Truncated" : "0 - Not Truncated"));
                flagsEntry.AddChildDetailsInfo(new("RD", msg.Header.HeaderFlags.HasFlag(HeaderFlags.RD) ? "1 - Recursion Desired" : "0 - Recursion Not Desired"));
                flagsEntry.AddChildDetailsInfo(new("RA", msg.Header.HeaderFlags.HasFlag(HeaderFlags.RA) ? "1 - Recursion Available" : "0 - Recursion Not Available"));
                flagsEntry.AddChildDetailsInfo(new("AD", msg.Header.HeaderFlags.HasFlag(HeaderFlags.AD) ? "1 - Authenticated" : "0 - Not Authenticated"));
                flagsEntry.AddChildDetailsInfo(new("CD", msg.Header.HeaderFlags.HasFlag(HeaderFlags.CD) ? "1 - Accept Non-Authenticated" : "0 - Not Accept Non-Authenticated"));
                flagsEntry.AddChildDetailsInfo(new("RCODE", msg.Header.RCODE.ToString()));
                result.Add(flagsEntry);
                result.Add(new TableRowDetailEntry(msg.Header.OpCode == OpCode.Update ? "ZoneCount" : "QuestionCount", msg.Header.QuestionCount.ToString()));
                result.Add(new TableRowDetailEntry(msg.Header.OpCode == OpCode.Update ? "PrerequisiteCount" : "AnswerCount", msg.Header.AnswerCount.ToString()));
                result.Add(new TableRowDetailEntry(msg.Header.OpCode == OpCode.Update ? "UpdateCount" : "AuthorityCount", msg.Header.AuthorityCount.ToString()));
                result.Add(new TableRowDetailEntry("AdditionalCount", msg.Header.AdditionalCount.ToString()));
                var qEntry = new TableRowDetailEntry(msg.Header.OpCode == OpCode.Update ? "Zone" : "Question");
                foreach (var q in msg.Questions)
                {
                    qEntry.AddChildDetailsInfo(new(q.QName.ToString(), $"type {q.QType} class {q.QClass}"));
                }
                var aEntry = new TableRowDetailEntry(msg.Header.OpCode == OpCode.Update ? "Prerequisites" : "Answers");
                foreach (var a in msg.Answers)
                {
                    var aChildEntry = new TableRowDetailEntry(a.Name.ToString(), $"type {a.Type} class {a.Class}");
                    aChildEntry.AddChildDetailsInfo(new("TTL", a.TTL.ToString()));
                    aChildEntry.AddChildDetailsInfo(new("DataLength", a.RDLength.ToString()));
                    aChildEntry.AddChildDetailsInfo(new("Data", a.RData.ToString()));
                    aEntry.AddChildDetailsInfo(aChildEntry);
                }
                var auEntry = new TableRowDetailEntry(msg.Header.OpCode == OpCode.Update ? "Updates" : "Authorities");
                foreach (var a in msg.Authorities)
                {
                    var aChildEntry = new TableRowDetailEntry(a.Name.ToString(), $"type {a.Type} class {a.Class}");
                    aChildEntry.AddChildDetailsInfo(new("TTL", a.TTL.ToString()));
                    aChildEntry.AddChildDetailsInfo(new("DataLength", a.RDLength.ToString()));
                    aChildEntry.AddChildDetailsInfo(new("Data", a.RData.ToString()));
                    auEntry.AddChildDetailsInfo(aChildEntry);
                }
                var adEntry = new TableRowDetailEntry("Additionals");
                foreach (var a in msg.Additionals)
                {
                    if (a.Type == RRType.OPT)
                    {
                        var aChildEntry = new TableRowDetailEntry(a.Name.ToString(), $"type {a.Type}");
                        aChildEntry.AddChildDetailsInfo(new("EDNS UDP Payload Size", a.EDNS_UdpPayloadSize.ToString()));
                        aChildEntry.AddChildDetailsInfo(new("EDNS Extended RCODE", a.EDNS_HighRCODE.ToString()));
                        aChildEntry.AddChildDetailsInfo(new("EDNS Version", a.EDNS_Version.ToString()));
                        aChildEntry.AddChildDetailsInfo(new("EDNS DO", a.EDNS_DO.ToString()));
                        aChildEntry.AddChildDetailsInfo(new("DataLength", a.RDLength.ToString()));
                        aChildEntry.AddChildDetailsInfo(new("Data", a.RData.ToString()));
                        adEntry.AddChildDetailsInfo(aChildEntry);
                    }
                    else
                    {
                        var aChildEntry = new TableRowDetailEntry(a.Name.ToString(), $"type {a.Type} class {a.Class}");
                        aChildEntry.AddChildDetailsInfo(new("TTL", a.TTL.ToString()));
                        aChildEntry.AddChildDetailsInfo(new("DataLength", a.RDLength.ToString()));
                        aChildEntry.AddChildDetailsInfo(new("Data", a.RData.ToString()));
                        adEntry.AddChildDetailsInfo(aChildEntry);
                    }
                }
                result.Add(qEntry);
                result.Add(aEntry);
                result.Add(auEntry);
                result.Add(adEntry);
            }
            catch (DnsParseException ex)
            {
                Console.WriteLine(ex.ToString());
            }

            return result;
        }
    }
}
