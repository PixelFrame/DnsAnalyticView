using System;
using System.Collections.Generic;
using System.Text;

namespace DnsAnalyticView
{
    internal class DnsUtilities
    {
        public static string FlagsToString(uint Flags)
        {
            var sb = new StringBuilder();
            if ((Flags & 0x8000) == 0) sb.Append("Q");
            else sb.Append("R");
            switch (Flags & 0x7800)
            {
                case 0: sb.Append(" | Query"); break;
                case 0x0800: sb.Append(" | IQuery"); break;
                case 0x1000: sb.Append(" | Status"); break;
                case 0x2000: sb.Append(" | Notify"); break;
                case 0x2800: sb.Append(" | Update"); break;
                case 0x3000: sb.Append(" | DSO"); break;
                default: sb.Append(" | Unassigned"); break;
            }
            if ((Flags & 0x400) != 0) sb.Append(" | AA");
            if ((Flags & 0x200) != 0) sb.Append(" | TC");
            if ((Flags & 0x100) != 0) sb.Append(" | RD");
            if ((Flags & 0x80) != 0) sb.Append(" | RA");
            if ((Flags & 0x40) != 0) sb.Append(" | Z");
            if ((Flags & 0x20) != 0) sb.Append(" | AD");
            if ((Flags & 0x10) != 0) sb.Append(" | CD");
            return sb.ToString();
        }

    }
}
