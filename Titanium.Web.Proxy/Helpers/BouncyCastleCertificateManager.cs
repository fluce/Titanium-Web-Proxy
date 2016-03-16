using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Titanium.Web.Proxy.Properties;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Titanium.Web.Proxy.Helpers
{
    public class BouncyCastleCertificateManager : ICertificateManager
    {
        private readonly string hashAlgorithm = "SHA256WITHRSA";

        private readonly int serverCertificateSize = 2048;

        private readonly int rootCertificateSize = 2048;

        public BouncyCastleCertificateManager(string issuer, string rootCertificateName, bool computerStore)
        {
            rootCN = rootCertificateName;
            certO = issuer;

            rootCAStoreLocation = computerStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser; 

            sharedKeyPair = new Lazy<AsymmetricCipherKeyPair>(GenerateKeyPair);
            reuseKeyPair = true;
        }

        #region Server certificate management

        public X509Certificate2 CreateCertificate(string sHostname)
        {
            return certCache.GetOrAdd(sHostname, x =>
            {
                EnsureRootCertificate();
                return CreateCertificateFromCA(sHostname, CACert, CAKey);
            });
        }
        private X509Certificate2 CreateCertificateFromCA(string sCN, X509Certificate caCert,
            AsymmetricKeyParameter caKey)
        {
            var kp = GetPublicPrivateKeyPair(sCN);

            var certificateGenerator = new X509V3CertificateGenerator();

            certificateGenerator.SetSerialNumber(new BigInteger(1, Guid.NewGuid().ToByteArray()));
            certificateGenerator.SetIssuerDN(caCert.IssuerDN);
            certificateGenerator.SetNotBefore(DateTime.Today.AddDays(-7));
            certificateGenerator.SetNotAfter(DateTime.Today.AddYears(2));

            certificateGenerator.SetSubjectDN(new X509Name(CalculateDN(sCN)));
            certificateGenerator.SetPublicKey(kp.Public);
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));
            var extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth);
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, extendedKeyUsage);

            var signatureFactory = new Asn1SignatureFactory(hashAlgorithm, caKey);

            var certBC = certificateGenerator.Generate(signatureFactory);

            var certDotNet = ConvertBCCertToDotNetCert(certBC);
            var cryptoServiceProvider = ConvertBCPrivateKeyToDotNet((RsaPrivateCrtKeyParameters)kp.Private);
            certDotNet.PrivateKey = cryptoServiceProvider;
            return certDotNet;
        }

        #endregion

        #region DN Management

        private string rootCN
        {
            get; set;
        }

        private string certOU => "Titanium Proxy";

        private string certO
        {
            get; set;
        }

        private string CalculateDN(string cn) => $"O={certO}, OU={certOU}, CN={cn}";
        private string CalculateStoreDN(string cn) => $"CN={cn}, OU={certOU}, O={certO}";

        #endregion

        #region Server Certificate cache management

        private readonly ConcurrentDictionary<string, X509Certificate2> certCache = new ConcurrentDictionary<string, X509Certificate2>();

        private void FlushCache()
        {
            var f = certCache.Keys.ToArray();
            foreach (var k in f)
            {
                X509Certificate2 cert = null;
                if (certCache.TryRemove(k, out cert))
                    FreePrivateKey(cert.PrivateKey);
            }
        }
        
        private void FreePrivateKey(AsymmetricAlgorithm oKey)
        {
            try
            {
                if (oKey == null)
                    return;
                var cryptoServiceProvider = oKey as RSACryptoServiceProvider;
                if (cryptoServiceProvider == null)
                    return;
                cryptoServiceProvider.PersistKeyInCsp = false;
                cryptoServiceProvider.Clear();
            }
            catch (Exception ex)
            {
            }
        }

        public bool ClearCertificateCache()
        {
            return ClearCertificateCache(true);
        }

        public bool ClearCertificateCache(bool bClearRoot)
        {
            try
            {
                FlushCache();
                if (bClearRoot)
                {
                    ClearRootCertificate();
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        #endregion

        #region Convert BouncyCastle formats to DotNet

        private static X509Certificate2 ConvertBCCertToDotNetCert(X509Certificate certBC)
        {
            return new X509Certificate2(DotNetUtilities.ToX509Certificate(certBC));
        }

        private RSACryptoServiceProvider ConvertBCPrivateKeyToDotNet(RsaPrivateCrtKeyParameters bcPVK)
        {
            var parameters = new CspParameters
            {
                KeyContainerName = certOU,
                Flags = CspProviderFlags.NoFlags
            };
            var cryptoServiceProvider = new RSACryptoServiceProvider(parameters);
            cryptoServiceProvider.ImportParameters(DotNetUtilities.ToRSAParameters(bcPVK));

            return cryptoServiceProvider;
        }

        #endregion

        #region Key pair management

        private readonly Lazy<AsymmetricCipherKeyPair> sharedKeyPair;
        private readonly bool reuseKeyPair;

        private AsymmetricCipherKeyPair GetPublicPrivateKeyPair(string sCN)
        {
            if (reuseKeyPair)
                return sharedKeyPair.Value;
            else
                return GenerateKeyPair();
        }

        private AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var random = new SecureRandom();
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(new KeyGenerationParameters(random, serverCertificateSize));
            return keyPairGenerator.GenerateKeyPair();
        }

        #endregion

        #region Root CA Certificate management

        private X509Certificate CACert;
        private AsymmetricKeyParameter CAKey;
        private readonly object CALock = new object();

        private void EnsureRootCertificate()
        {
            if ((CACert == null || CAKey == null))
                CreateRootCertificate();
        }

        public X509Certificate2 RootCertificate
        {
            get
            {
                if (CACert == null && !LoadRootCertificate())
                    return null;
                return ConvertBCCertToDotNetCert(CACert);
            }
        }

        public bool CreateRootCertificate()
        {
            lock (CALock)
            {
                if (CAKey != null && CACert != null)
                {
                    return true;
                }
                if (LoadRootCertificate())
                    return true;

                var dn = new X509Name(CalculateDN(rootCN));

                var kpGenerator = new RsaKeyPairGenerator();
                kpGenerator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()),
                    rootCertificateSize));
                var kp = kpGenerator.GenerateKeyPair();

                var certificateGenerator = new X509V3CertificateGenerator();
                certificateGenerator.SetSerialNumber(new BigInteger(0,Guid.NewGuid().ToByteArray()));
                certificateGenerator.SetIssuerDN(dn);
                certificateGenerator.SetSubjectDN(dn);
                certificateGenerator.SetNotBefore(DateTime.Today.AddDays(-7.0));
                certificateGenerator.SetNotAfter(DateTime.Now.AddYears(10));
                certificateGenerator.SetPublicKey(kp.Public);
                certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
                certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(4));
                certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(kp.Public));

                var signatureFactory = new Asn1SignatureFactory(hashAlgorithm, kp.Private);

                CACert = certificateGenerator.Generate(signatureFactory);
                CAKey = kp.Private;
            }
            StoreRootCertificate();
            if (!RootCertIsTrusted())
                TrustRootCertificate();
            return true;
        }


        #endregion

        #region Root CA certificate persistence

        private void StoreRootCertificate()
        {
            if (CACert == null)
                Settings.Default.CACert = "";
            else
                Settings.Default.CACert = Convert.ToBase64String(CACert.GetEncoded());

            if (CAKey == null)
                Settings.Default.CAPrivateKey = "";
            else
                Settings.Default.CAPrivateKey =
                    Convert.ToBase64String(PrivateKeyInfoFactory.CreatePrivateKeyInfo(CAKey).ToAsn1Object().GetDerEncoded());
            Settings.Default.Save();
        }

        private bool LoadRootCertificate()
        {
            var cert = Settings.Default.CACert;
            var key = Settings.Default.CAPrivateKey;
            if (!string.IsNullOrEmpty(cert) && !string.IsNullOrEmpty(key))
            {
                try
                {
                    CACert = new X509CertificateParser().ReadCertificate(Convert.FromBase64String(cert));
                    CAKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(key));
                    return true;
                }
                catch (Exception ex)
                {
                    CACert = null;
                    CAKey = null;
                    return false;
                }
            }
            return false;
        }
        #endregion

        #region Root CA trust management

        private StoreLocation rootCAStoreLocation { get; set; }

        private static void AddBCCertToStore(string sFriendlyName, X509Certificate newCert, StoreLocation oSL,
    StoreName oSN)
        {
            var certificate = ConvertBCCertToDotNetCert(newCert);
            certificate.FriendlyName = sFriendlyName;
            var x509Store = new X509Store(oSN, oSL);
            x509Store.Open(OpenFlags.ReadWrite);
            try
            {
                x509Store.Add(certificate);
            }
            finally
            {
                x509Store.Close();
            }
        }

        private X509Certificate2Collection FindCertsByIssuer(StoreName storeName, StoreLocation storeLocation,
                                                         string sFullIssuerSubject)
        {
            try
            {
                var x509Store = new X509Store(storeName, storeLocation);
                x509Store.Open(OpenFlags.OpenExistingOnly);
                var certificate2Collection = x509Store.Certificates.Find(X509FindType.FindByIssuerDistinguishedName,
                    sFullIssuerSubject, false);
                x509Store.Close();
                return certificate2Collection;
            }
            catch (Exception ex)
            {
                return new X509Certificate2Collection();
            }
        }


        public bool TrustRootCertificate()
        {
            if (CACert == null)
            {
                return false;
            }
            try
            {
                AddBCCertToStore(rootCN, CACert, rootCAStoreLocation, StoreName.Root);
            }
            catch (Exception ex)
            {
                return false;
            }
            return true;
        }

        public bool RootCertIsTrusted()
        {
            bool bUserTrusted;
            bool bMachineTrusted;
            return RootCertIsTrusted(out bUserTrusted, out bMachineTrusted);
        }

        public bool RootCertIsTrusted(out bool bUserTrusted, out bool bMachineTrusted)
        {
            var certsByIssuer1 = FindCertsByIssuer(StoreName.Root, StoreLocation.CurrentUser, CalculateStoreDN(rootCN));

            var serial = CACert.SerialNumber.ToString(16);

            bUserTrusted = certsByIssuer1.Find(X509FindType.FindBySerialNumber, serial, false).Count > 0;
            var certsByIssuer2 = FindCertsByIssuer(StoreName.Root, StoreLocation.LocalMachine, CalculateStoreDN(rootCN));

            bMachineTrusted = certsByIssuer2.Find(X509FindType.FindBySerialNumber, serial, false).Count > 0;

            return bMachineTrusted || bUserTrusted;
        }

        private void ClearRootCertificate()
        {
            CACert = null;
            CAKey = null;
            StoreRootCertificate();

            var certsByIssuer = FindCertsByIssuer(StoreName.Root, rootCAStoreLocation, CalculateStoreDN(rootCN));
            if (certsByIssuer.Count > 0)
            {
                try
                {
                    var x509Store = new X509Store(StoreName.Root, rootCAStoreLocation);
                    x509Store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                    try
                    {
                        x509Store.RemoveRange(certsByIssuer);
                    }
                    catch
                    {
                    }
                    x509Store.Close();
                }
                catch
                {
                }
            }
        }
        #endregion

        public void Dispose()
        {
            FlushCache();
        }


    }
}