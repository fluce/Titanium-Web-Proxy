using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Helpers;
using Titanium.Web.Proxy.Models;
using Titanium.Web.Proxy.Network;
using System.Linq;
using System.Security.Authentication;

namespace Titanium.Web.Proxy
{
    /// <summary>
    ///     Proxy Server Main class
    /// </summary>
    public partial class ProxyServer
    {
       
        private static readonly char[] SemiSplit = { ';' };

        private static readonly string[] ColonSpaceSplit = { ": " };
        private static readonly char[] SpaceSplit = { ' ' };

        private static readonly Regex CookieSplitRegEx = new Regex(@",(?! )");

        private static readonly byte[] NewLineBytes = Encoding.ASCII.GetBytes(Environment.NewLine);

        private static readonly byte[] ChunkEnd =
            Encoding.ASCII.GetBytes(0.ToString("x2") + Environment.NewLine + Environment.NewLine);

        public static readonly int BUFFER_SIZE = 8192;
#if NET45
        internal static SslProtocols SupportedProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Ssl3;
#else
        internal static SslProtocols SupportedProtocols  = SslProtocols.Tls | SslProtocols.Ssl3;
#endif

        public ProxyServer()
        {
            
            ProxyEndPoints = new List<ProxyEndPoint>();
            TcpConnectionManager = new TcpConnectionManager();

            Initialize();
        }

        private ICertificateManager CertManager { get; set; }
        public ITcpConnectionManager TcpConnectionManager { get; set; }
        private bool EnableSsl { get; set; }
        private bool certTrusted { get; set; }
        private bool proxyRunning { get; set; }

        public string RootCertificateIssuerName { get; set; }
        public string RootCertificateName { get; set; }

        public event EventHandler<SessionEventArgs> BeforeRequest;
        public event EventHandler<SessionEventArgs> BeforeResponse;

        public List<ProxyEndPoint> ProxyEndPoints { get; set; }

        public void Initialize()
        {
            Task.Factory.StartNew(() => TcpConnectionManager.ClearIdleConnections());
        }

        public void AddEndPoint(ProxyEndPoint endPoint)
        {
            ProxyEndPoints.Add(endPoint);

            if (proxyRunning)
                Listen(endPoint);
        }

        public void RemoveEndPoint(ProxyEndPoint endPoint)
        {

            if (ProxyEndPoints.Contains(endPoint) == false)
                throw new Exception("Cannot remove endPoints not added to proxy");

            ProxyEndPoints.Remove(endPoint);

            if (proxyRunning)
                QuitListen(endPoint);
        }


        public void SetAsSystemHttpProxy(ExplicitProxyEndPoint endPoint)
        {
            VerifyProxy(endPoint);

            //clear any settings previously added
            ProxyEndPoints.OfType<ExplicitProxyEndPoint>().ToList().ForEach(x => x.IsSystemHttpProxy = false);

            SystemProxyHelper.SetHttpProxy(
                Equals(endPoint.IpAddress, IPAddress.Any) | Equals(endPoint.IpAddress, IPAddress.Loopback) ? "127.0.0.1" : endPoint.IpAddress.ToString(), endPoint.Port);

            endPoint.IsSystemHttpProxy = true;
#if !DEBUG
            FireFoxHelper.AddFirefox();
#endif
            Console.WriteLine("Set endpoint at Ip {1} and port: {2} as System HTTPS Proxy", endPoint.GetType().Name, endPoint.IpAddress, endPoint.Port);

        }

        public static void DisableSystemHttpProxy()
        {
            SystemProxyHelper.RemoveHttpProxy();
        }

        public void SetAsSystemHttpsProxy(ExplicitProxyEndPoint endPoint)
        {
            VerifyProxy(endPoint);

            if (!endPoint.EnableSsl)
            {
                throw new Exception("Endpoint do not support Https connections");
            }

            //clear any settings previously added
            ProxyEndPoints.OfType<ExplicitProxyEndPoint>().ToList().ForEach(x => x.IsSystemHttpsProxy = false);


            //If certificate was trusted by the machine
            if (certTrusted)
            {
                SystemProxyHelper.SetHttpsProxy(
                   Equals(endPoint.IpAddress, IPAddress.Any) | Equals(endPoint.IpAddress, IPAddress.Loopback) ? "127.0.0.1" : endPoint.IpAddress.ToString(),
                    endPoint.Port);
            }

            endPoint.IsSystemHttpsProxy = true;

#if !DEBUG
            FireFoxHelper.AddFirefox();
#endif
            Console.WriteLine("Set endpoint at Ip {1} and port: {2} as System HTTPS Proxy", endPoint.GetType().Name, endPoint.IpAddress, endPoint.Port);
        }

        public static void DisableSystemHttpsProxy()
        {
            SystemProxyHelper.RemoveHttpsProxy();
        }

        public static void DisableAllSystemProxies()
        {
            SystemProxyHelper.DisableAllProxy();
        }

        public void Start()
        {
            if (proxyRunning)
                throw new Exception("Proxy is already running.");

            RootCertificateName = RootCertificateName ?? "Titanium Root Certificate Authority";
            RootCertificateIssuerName = RootCertificateIssuerName ?? "Titanium";

            CertManager = new BouncyCastleCertificateManager(RootCertificateIssuerName,
                RootCertificateName, true);

            EnableSsl = ProxyEndPoints.Any(x => x.EnableSsl);

            if (EnableSsl)
                certTrusted = CertManager.CreateRootCertificate();

            foreach (var endPoint in ProxyEndPoints)
            {
                Listen(endPoint);
            }

            proxyRunning = true;
        }

        public void Stop()
        {
            if (!proxyRunning)
                throw new Exception("Proxy is not running.");

            var setAsSystemProxy = ProxyEndPoints.OfType<ExplicitProxyEndPoint>().Any(x => x.IsSystemHttpProxy || x.IsSystemHttpsProxy);

            if (setAsSystemProxy)
            {
                SystemProxyHelper.DisableAllProxy();
#if !DEBUG
                FireFoxHelper.RemoveFirefox();
#endif
            }

            foreach (var endPoint in ProxyEndPoints)
            {
                endPoint.listener.Stop();
            }

            CertManager.Dispose();

            proxyRunning = false;
        }

        private  void Listen(ProxyEndPoint endPoint)
        {
            endPoint.listener = new TcpListener(endPoint.IpAddress, endPoint.Port);
            endPoint.listener.Start();

            endPoint.Port = ((IPEndPoint)endPoint.listener.LocalEndpoint).Port;
            // accept clients asynchronously
            endPoint.listener.BeginAcceptTcpClient(OnAcceptConnection, endPoint);
        }

        private static void QuitListen(ProxyEndPoint endPoint)
        {
            endPoint.listener.Stop();
        }


        private void VerifyProxy(ExplicitProxyEndPoint endPoint)
        {
            if (ProxyEndPoints.Contains(endPoint) == false)
                throw new Exception("Cannot set endPoints not added to proxy as system proxy");

            if (!proxyRunning)
                throw new Exception("Cannot set system proxy settings before proxy has been started.");
        }

        private void OnAcceptConnection(IAsyncResult asyn)
        {
            var endPoint = (ProxyEndPoint)asyn.AsyncState;

            try
            {
                var client = endPoint.listener.EndAcceptTcpClient(asyn);
                if (endPoint.GetType() == typeof(TransparentProxyEndPoint))
                    Task.Factory.StartNew(() => HandleClient(endPoint as TransparentProxyEndPoint, client));
                else
                    Task.Factory.StartNew(() => HandleClient(endPoint as ExplicitProxyEndPoint, client));

                // Get the listener that handles the client request.
                endPoint.listener.BeginAcceptTcpClient(OnAcceptConnection, endPoint);
            }
            catch
            {
                // ignored
            }

            
        }
     
    }
}