﻿// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.Net;
using System.Linq;
using System.Threading;
using System.Net.Sockets;
using System.Collections.Generic;

using SharpSploit.Generic;

namespace SharpSploit.Pivoting
{
    /// <summary>
    /// PortForwarding is a library for managing port forwards.
    /// </summary>
    public class PortForwarding
    {
        public class ReversePortForward
        {
            public IPAddress[] BindAddresses { get; set; }
            public int BindPort { get; set; }
            public IPAddress ForwardAddress { get; set; }
            public int ForwardPort { get; set; }
        }

        public static List<ReversePortForward> _reversePortForwards = new List<ReversePortForward>();
        public static List<Dictionary<int, List<Socket>>> _serverSockets = new List<Dictionary<int, List<Socket>>>();

        /// <summary>
        /// Starts a new ReversePortForward.
        /// </summary>
        /// <param name="BindPort">The port to bind to.</param>
        /// <param name="ForwardAddress">The IP Address or DNS entry to forward traffic to.</param>
        /// <param name="ForwardPort">The port to forward traffic to.</param>
        /// <returns>Bool. True if successful, otherwise false.</returns>
        public static bool StartReversePortForward(string BindPort, string ForwardAddress, string ForwardPort)
        {
            var bindAddresses = new IPAddress[] { IPAddress.Any };

            if (!int.TryParse(BindPort, out int bindPort))
                return false;

            //var forwardAddress = IPAddress.Parse(ForwardAddress);

            if (!IPAddress.TryParse(ForwardAddress, out IPAddress forwardAddress))
            {
                try {
                    var ipHostInfo = Dns.GetHostEntry(ForwardAddress);
                    forwardAddress = ipHostInfo.AddressList[0];
                }
                catch (SocketException) { return false; }
            }

            if (!int.TryParse(ForwardPort, out int forwardPort))
                return false;

            // Check not already bound
            foreach (var serverSocket in _serverSockets)
                if (serverSocket.ContainsKey(int.Parse(BindPort)))
                    return false;

            // Else bind the port on all interfaces
            var serverSockets = CreateServerSockets(bindAddresses, bindPort);

            if (serverSockets != null && serverSockets.Count > 0)
            {
                // Create new object
                var reversePortForward = new ReversePortForward
                {
                    BindAddresses = bindAddresses,
                    BindPort = bindPort,
                    ForwardAddress = forwardAddress,
                    ForwardPort = forwardPort
                };

                // Add object to list
                _reversePortForwards.Add(reversePortForward);

                // Add sockets to list
                _serverSockets.Add(new Dictionary<int, List<Socket>> { { bindPort, serverSockets } });

                // Kick off the client sockets in a new thread
                var thread = new Thread(() => ClientSocketThread(serverSockets, forwardAddress, forwardPort));
                thread.Start();

                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Accepts data on bound sockets, creates new client sockets, forwards data and relays responses back.
        /// </summary>
        /// <param name="serverSockets">A list of bound Sockets.</param>
        /// <param name="forwardAddress">The IP address to forward traffic to.</param>
        /// <param name="forwardPort">The port to forward traffic to.</param>
        private static void ClientSocketThread(List<Socket> serverSockets, IPAddress forwardAddress, int forwardPort)
        {
            var remoteEndPoint = new IPEndPoint(forwardAddress, forwardPort);

            while (true)
            {
                byte[] serverBuffer = new byte[1024];
                byte[] clientBuffer = new byte[1048576];

                // Recieve data on bind address
                foreach (var serverSocket in serverSockets)
                {
                    try
                    {
                        var serverHandler = serverSocket.Accept();
                        var bytesFromBind = serverHandler.Receive(serverBuffer);

                        using (var clientSocket = new Socket(forwardAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                        {
                            try
                            {
                                clientSocket.Connect(remoteEndPoint);

                                // Send data to forward address
                                clientSocket.Send(serverBuffer);
                                var bytesFromFwd = clientSocket.Receive(clientBuffer);
                            }
                            catch (SocketException) { }
                        }

                        // Send data back to client
                        serverHandler.Send(clientBuffer);
                    }
                    catch { }
                }
            }
        }

        /// <summary>
        /// Stops the Reverse Port Forward bound on the specified port.
        /// </summary>
        /// <param name="BindPort">The Port the socket is bound to.</param>
        /// <returns>Bool. True if successful, otherwise false.</returns>
        public static bool StopReversePortForward(string BindPort)
        {
            // Check if any bound sockets exit
            if (_serverSockets.Count == 0)
                return false;

            // Iterate through List
            try
            {
                foreach (var serverSocket in _serverSockets)
                {
                    // Get the list of Sockets for the bound port
                    if (serverSocket.TryGetValue(int.Parse(BindPort), out List<Socket> sockets))
                    {
                        // Shutdown and/or Close Sockets
                        foreach (var socket in sockets)
                        {
                            try { socket.Shutdown(SocketShutdown.Both); }
                            catch { }

                            socket.Close();
                        }

                        // Remove Socket dictionary from List
                        _serverSockets.Remove(serverSocket);
                    }
                }
            }
            catch { }

            // Remove the ReversePortForward object from List
            var reversePortForward = _reversePortForwards.Where(r => r.BindPort == int.Parse(BindPort)).SingleOrDefault();
            _reversePortForwards.Remove(reversePortForward);

            return true;
        }

        /// <summary>
        /// Get's a list of active Reverse Port Fowards.
        /// </summary>
        /// <returns></returns>
        public static SharpSploitResultList<ReversePortFwdResult> GetActiveReversePortForwards()
        {
            var results = new SharpSploitResultList<ReversePortFwdResult>();

            foreach (var reversePortForward in _reversePortForwards)
            {
                var bindAddressesArr = reversePortForward.BindAddresses.Select(ip => ip.ToString()).ToArray();
                var bindAddresses = string.Join(",", bindAddressesArr);

                results.Add(new ReversePortFwdResult
                {
                    BindAddresses = bindAddresses,
                    BindPort = reversePortForward.BindPort,
                    ForwardAddress = reversePortForward.ForwardAddress.ToString(),
                    FowardPort = reversePortForward.ForwardPort
                });
            }

            return results;
        }

        /// <summary>
        /// Binds a port to the specified IP Addresses.
        /// </summary>
        /// <param name="BindAddresses">An IPAddress array to bind to.</param>
        /// <param name="BindPort">The port to bind on.</param>
        /// <returns>A list of Sockets.</returns>
        private static List<Socket> CreateServerSockets(IPAddress[] BindAddresses, int BindPort)
        {
            var socketList = new List<Socket>();

            foreach (var bindAddress in BindAddresses)
            {
                var localEndPoint = new IPEndPoint(bindAddress, BindPort);
                var serverSocket = new Socket(bindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    serverSocket.Bind(localEndPoint);
                    serverSocket.Listen(10);

                    socketList.Add(serverSocket);
                }
                catch (SocketException) { return null; }
            }

            return socketList;
        }

        /// <summary>
        /// Represents an active Reverse Port Forward, used with GetActiveReversePortForwards().
        /// </summary>
        public sealed class ReversePortFwdResult : SharpSploitResult
        {
            public string BindAddresses { get; set; }
            public int BindPort { get; set; }
            public string ForwardAddress { get; set; }
            public int FowardPort { get; set; }
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty> {
                        new SharpSploitResultProperty { Name = "BindAddresses", Value = this.BindAddresses },
                        new SharpSploitResultProperty { Name = "BindPort", Value = this.BindPort },
                        new SharpSploitResultProperty { Name = "ForwardAddress", Value = this.ForwardAddress },
                        new SharpSploitResultProperty { Name = "FowardPort", Value = this.FowardPort }
                    };
                }
            }
        }
    }
}