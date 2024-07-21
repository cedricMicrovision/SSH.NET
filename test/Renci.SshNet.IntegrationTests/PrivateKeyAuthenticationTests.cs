using Renci.SshNet.IntegrationTests.Common;
using Renci.SshNet.TestTools.OpenSSH;

namespace Renci.SshNet.IntegrationTests
{
    [TestClass]
    public class PrivateKeyAuthenticationTests : TestBase
    {
        private IConnectionInfoFactory _connectionInfoFactory;
        private RemoteSshdConfig _remoteSshdConfig;

        [TestInitialize]
        public void SetUp()
        {
            _connectionInfoFactory = new LinuxVMConnectionFactory(SshServerHostName, SshServerPort);
            _remoteSshdConfig = new RemoteSshd(new LinuxAdminConnectionFactory(SshServerHostName, SshServerPort)).OpenConfig();
        }

        [TestCleanup]
        public void TearDown()
        {
            _remoteSshdConfig?.Reset();
        }

        [TestMethod]
        public void SshDss()
        {
            DoTest(PublicKeyAlgorithm.SshDss, "Data.Key.SSH2.DSA.Encrypted.Des.CBC.12345.txt", "12345");
        }

        [TestMethod]
        public void SshRsa()
        {
            DoTest(PublicKeyAlgorithm.SshRsa, "Data.Key.RSA.txt");
        }

        [TestMethod]
        public void SshRsaSha256()
        {
            DoTest(PublicKeyAlgorithm.RsaSha2256, "Data.Key.RSA.txt");
        }

        [TestMethod]
        public void SshRsaSha512()
        {
            DoTest(PublicKeyAlgorithm.RsaSha2512, "Data.Key.RSA.txt");
        }

        [TestMethod]
        public void Ecdsa256()
        {
            DoTest(PublicKeyAlgorithm.EcdsaSha2Nistp256, "Data.Key.ECDSA.Encrypted.txt", "12345");
        }

        [TestMethod]
        public void Ecdsa384()
        {
            DoTest(PublicKeyAlgorithm.EcdsaSha2Nistp384, "Data.Key.OPENSSH.ECDSA384.Encrypted.txt", "12345");
        }

        [TestMethod]
        public void Ecdsa521()
        {
            DoTest(PublicKeyAlgorithm.EcdsaSha2Nistp521, "Data.Key.OPENSSH.ECDSA521.Encrypted.txt", "12345");
        }

        [TestMethod]
        public void Ed25519()
        {
            DoTest(PublicKeyAlgorithm.SshEd25519, "Data.Key.OPENSSH.ED25519.Encrypted.txt", "12345");
        }

        [TestMethod]
        public void SshRsaCertificate()
        {
            // ssh-keygen -L -f Key.OPENSSH.RSA-cert.pub
            //    Type: ssh-rsa-cert-v01@openssh.com user certificate
            //    Public key: RSA-CERT SHA256:Eakx9OK+zveFGPECEGY55TokNKde5GjfQkTHHT1PNfs
            //    Signing CA: RSA SHA256:NqLEgdYti0XjUkYjGyQv2Ddy1O5v2NZDZFRtlfESLIA (using rsa-sha2-512)
            // And we will authenticate (sign) with ssh-rsa (SHA-1)
            DoTest(PublicKeyAlgorithm.SshRsaCertV01OpenSSH, "Data.Key.OPENSSH.RSA.txt", certificateResource: "Data.Key.OPENSSH.RSA-cert.pub");
        }

        [TestMethod]
        public void SshRsaSha256Certificate()
        {
            // As above, but we will authenticate (sign) with rsa-sha2-256
            DoTest(PublicKeyAlgorithm.RsaSha2256CertV01OpenSSH, "Data.Key.OPENSSH.RSA.txt", certificateResource: "Data.Key.OPENSSH.RSA-cert.pub");
        }

        [TestMethod]
        public void Ed25519Certificate()
        {
            // ssh-keygen -L -f Key.OPENSSH.ED25519-cert.pub
            //    Type: ssh-ed25519-cert-v01@openssh.com user certificate
            //    Public key: ED25519-CERT SHA256:e9CGro9Y4buSpUIiLMlBPzHY/YrZZxTuMIryqFknXBI
            //    Signing CA: ECDSA SHA256:r/t6I+bZQzN5BhSuntFSHDHlrnNHVM2lAo6gbvynG/4 (using ecdsa-sha2-nistp256)
            DoTest(PublicKeyAlgorithm.SshEd25519CertV01OpenSSH, "Data.Key.OPENSSH.ED25519.txt", certificateResource: "Data.Key.OPENSSH.ED25519-cert.pub");
        }

        private void DoTest(PublicKeyAlgorithm publicKeyAlgorithm, string keyResource, string passPhrase = null, string certificateResource = null)
        {
            _remoteSshdConfig.ClearPublicKeyAcceptedAlgorithms()
                             .AddPublicKeyAcceptedAlgorithm(publicKeyAlgorithm)
                             .Update()
                             .Restart();

            var connectionInfo = _connectionInfoFactory.Create(CreatePrivateKeyAuthenticationMethod(keyResource, passPhrase, certificateResource));

            using (var client = new SshClient(connectionInfo))
            {
                client.Connect();
            }
        }

        private static PrivateKeyAuthenticationMethod CreatePrivateKeyAuthenticationMethod(string keyResource, string passPhrase, string certificateResource)
        {
            PrivateKeyFile privateKey;

            using (var keyStream = GetData(keyResource))
            {
                if (certificateResource is not null)
                {
                    using (var certificateStream = GetData(certificateResource))
                    {
                        privateKey = new PrivateKeyFile(keyStream, passPhrase, certificateStream);
                    }
                }
                else
                {
                    privateKey = new PrivateKeyFile(keyStream, passPhrase);
                }
            }

            return new PrivateKeyAuthenticationMethod(Users.Regular.UserName, privateKey);
        }
    }
}
