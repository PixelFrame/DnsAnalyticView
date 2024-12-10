using DnsAnalyticView;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;

namespace DnsAnalytic2Pcap
{
    internal class DnsAnalyticPacketWriter : IDisposable
    {
        private static readonly PhysicalAddress ethSrc = PhysicalAddress.Parse("12-34-56-78-90-AA");
        private static readonly PhysicalAddress ethDst = PhysicalAddress.Parse("12-34-56-78-90-AB");

        private readonly CaptureFileWriterDevice writer;
        private static readonly DateTime epoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public DnsAnalyticPacketWriter(string pcapFile)
        {
            writer = new CaptureFileWriterDevice(pcapFile, FileMode.Create);
            var config = new DeviceConfiguration()
            {
                LinkLayerType = LinkLayers.Ethernet,
            };
            writer.Open(config);
        }

        internal void ConstructPacket(DnsAnalyticThinEvent e)
        {
            var ethPacket = new EthernetPacket(ethSrc, ethDst, EthernetType.None);

            if (e.SrcAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var ipv4Packet = new IPv4Packet(e.SrcAddr, e.DstAddr);
                ipv4Packet.ParentPacket = ethPacket;
                ethPacket.PayloadPacket = ipv4Packet;
            }
            else
            {
                var ipv6Packet = new IPv6Packet(e.SrcAddr, e.DstAddr);
                ipv6Packet.ParentPacket = ethPacket;
                ethPacket.PayloadPacket = ipv6Packet;
            }
            if (e.TCP)
            {
                var dnsLen = BitConverter.GetBytes(e.PacketData.Length);
                var tcpPayload = e.PacketData.Prepend(dnsLen[1]).Prepend(dnsLen[0]).ToArray();
                var tcpPacket = new TcpPacket((ushort)e.SrcPort, (ushort)e.DstPort)
                {
                    PayloadData = tcpPayload
                };
                tcpPacket.ParentPacket = ethPacket.PayloadPacket;
                ethPacket.PayloadPacket.PayloadPacket = tcpPacket;
                tcpPacket.UpdateTcpChecksum();
            }
            else
            {
                var udpPacket = new UdpPacket((ushort)e.SrcPort, (ushort)e.DstPort)
                {
                    PayloadData = [.. e.PacketData]
                };
                udpPacket.ParentPacket = ethPacket.PayloadPacket;
                ethPacket.PayloadPacket.PayloadPacket = udpPacket;
                udpPacket.UpdateUdpChecksum();
            }

            var header = new PcapHeader((uint)e.Timestamp.ToUniversalTime().Subtract(epoch).TotalSeconds, (uint)(e.Timestamp.Millisecond * 1000 + e.Timestamp.Microsecond), (uint)ethPacket.Bytes.Length, (uint)ethPacket.Bytes.Length);

            writer.Write(ethPacket.Bytes, ref header);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (writer.Opened) writer.Close();
                writer.Dispose();
            }
        }
    }
}
