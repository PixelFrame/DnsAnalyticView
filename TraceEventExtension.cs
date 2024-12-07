using Microsoft.Diagnostics.Tracing;
using System;
using System.Collections.Generic;
using System.Text;

namespace DnsAnalyticView
{
    internal static class TraceEventExtension
    {
        public static uint UIntPayloadByName(this TraceEvent Event, string Name, uint DefaultVal = 0)
        {
            var p = Event.PayloadByName(Name);
            if (p == null) 
            {
                return DefaultVal; 
            }
            else
            {
                return Convert.ToUInt32(p);         // Cannot directly cast here, as the type from merged traces will be int
            }
        }

        public static bool BooleanPayloadByName(this TraceEvent Event, string Name, bool DefaultVal = false)
        {
            var p = Event.PayloadByName(Name);
            if (p == null)
            {
                return DefaultVal;
            }
            else
            {
                return (byte)p != 0;
            }
        }
    }
}
