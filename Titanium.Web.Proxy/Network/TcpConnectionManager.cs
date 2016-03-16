﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Security;
using Titanium.Web.Proxy.Helpers;
using System.Threading;
using System.Security.Authentication;

namespace Titanium.Web.Proxy.Network
{
    public class TcpConnection
    {
        public string HostName { get; set; }
        public int port { get; set; }
        public bool IsSecure { get; set; }

        public TcpClient TcpClient { get; set; }
        public CustomBinaryReader ServerStreamReader { get; set; }
        public Stream Stream { get; set; }

        public DateTime LastAccess { get; set; }

        public TcpConnection()
        {
            LastAccess = DateTime.Now;
        }
    }

    public interface ITcpConnectionManager
    {
        TcpConnection GetClient(string Hostname, int port, bool IsSecure);
        void ReleaseClient(TcpConnection Connection);
        void ClearIdleConnections();
        Func<string, IPAddress> ResolveHostNameCallback { get; set; }
    }

    public class TcpConnectionManager : ITcpConnectionManager
    {
        List<TcpConnection> ConnectionCache = new List<TcpConnection>();

        public Func<string,IPAddress> ResolveHostNameCallback { get; set; }

        public TcpConnection GetClient(string Hostname, int port, bool IsSecure)
        {
            TcpConnection cached = null;
            while (true)
            {
                lock (ConnectionCache)
                {
                    cached =
                        ConnectionCache.FirstOrDefault(
                            x =>
                                x.HostName == Hostname && x.port == port && x.IsSecure == IsSecure &&
                                x.TcpClient.Connected);

                    if (cached != null)
                        ConnectionCache.Remove(cached);
                }

                if (cached != null && !cached.TcpClient.Client.IsConnected())
                    continue;

                if (cached == null)
                    break;
            }

            if (cached == null)
                cached = CreateClient(Hostname, port, IsSecure);

            if (
                ConnectionCache.Where(
                    x => x.HostName == Hostname && x.port == port && x.IsSecure == IsSecure && x.TcpClient.Connected)
                    .Count() < 2)
            {
                Task.Factory.StartNew(() => ReleaseClient(CreateClient(Hostname, port, IsSecure)));
            }

            return cached;
        }

        public virtual IPAddress ResolveHostName(string hostname)
        {
            return ResolveHostNameCallback?.Invoke(hostname);
        }

        private TcpConnection CreateClient(string Hostname, int port, bool IsSecure)
        {
            IPAddress address = ResolveHostName(Hostname);
            TcpClient client;
            if (address != null)
            {
                client = new TcpClient(address.ToString(),port);
            }
            else
                client = new TcpClient(Hostname, port);

            var stream = (Stream) client.GetStream();

            if (IsSecure)
            {
                var sslStream = (SslStream) null;
                try
                {
                    sslStream = new SslStream(stream);
                    sslStream.AuthenticateAsClient(Hostname, null, ProxyServer.SupportedProtocols, false);
                    stream = (Stream) sslStream;
                }
                catch
                {
                    if (sslStream != null)
                        sslStream.Dispose();
                    throw;
                }
            }

            return new TcpConnection()
            {
                HostName = Hostname,
                port = port,
                IsSecure = IsSecure,
                TcpClient = client,
                ServerStreamReader = new CustomBinaryReader(stream, Encoding.ASCII),
                Stream = stream
            };
        }

        public void ReleaseClient(TcpConnection Connection)
        {
            Connection.LastAccess = DateTime.Now;
            ConnectionCache.Add(Connection);
        }

        public void ClearIdleConnections()
        {
            while (true)
            {
                lock (ConnectionCache)
                {
                    var cutOff = DateTime.Now.AddSeconds(-60);

                    ConnectionCache
                        .Where(x => x.LastAccess < cutOff)
                        .ToList()
                        .ForEach(x => x.TcpClient.Close());

                    ConnectionCache.RemoveAll(x => x.LastAccess < cutOff);
                }

                Thread.Sleep(1000*60*3);
            }

        }


    }
}
