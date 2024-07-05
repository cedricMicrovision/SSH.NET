using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using Renci.SshNet.Security;
using Renci.SshNet.Security.Cryptography;
using Renci.SshNet.Tests.Common;

namespace Renci.SshNet.Tests.Classes.Security.Cryptography
{
    /// <summary>
    /// Implements RSA digital signature algorithm.
    /// </summary>
    [TestClass]
    public class DsaDigitalSignatureTest : TestBase
    {
        [TestMethod]
        public void SignAndVerify_1024_160()
        {
            byte[] data = Encoding.UTF8.GetBytes("hello world");

            DsaKey dsaKey = GetDsaKey("Key.SSH2.DSA.Encrypted.Des.Ede3.CBC.12345.txt", "12345");

            Assert.AreEqual(1024, dsaKey.P.BitLength);
            Assert.AreEqual(160, dsaKey.Q.BitLength);

            var digitalSignature = new DsaDigitalSignature(dsaKey);

            byte[] signedBytes = digitalSignature.Sign(data);

            byte[] expectedSignedBytes = new byte[]
            {
                // echo -n 'hello world' | openssl dgst -sha1 -sign Key.DSA.txt -out test.signed
                0x30, 0x44, 0x02, 0x20, 0x71, 0xf2, 0xe1, 0x88, 0xbf, 0x31, 0xc2, 0xbc, 0x22, 0xc7, 0x27, 0x1a,
                0xfe, 0x73, 0x6a, 0x16, 0xb1, 0x87, 0xf9, 0x7c, 0x7b, 0x45, 0x85, 0xae, 0xde, 0xcc, 0xed, 0x3e,
                0x99, 0x04, 0x09, 0xfd, 0x02, 0x20, 0x32, 0x29, 0x81, 0xd6, 0x4d, 0xd7, 0xb0, 0x10, 0x76, 0x42,
                0x0f, 0x92, 0x7e, 0x16, 0x7d, 0xf3, 0xc6, 0x20, 0x11, 0x55, 0x7a, 0x14, 0x07, 0xba, 0x63, 0x34,
                0x2d, 0x3d, 0xfe, 0xb8, 0xad, 0xa2
            };

            CollectionAssert.AreEqual(expectedSignedBytes, signedBytes);

            Assert.IsTrue(digitalSignature.Verify(data, signedBytes));
        }

        [TestMethod]
        public void SignAndVerify_3072_256()
        {
            byte[] data = Encoding.UTF8.GetBytes("hello world");

            DsaKey dsaKey = GetDsaKey("Key.DSA.txt");

            Assert.AreEqual(3072, dsaKey.P.BitLength);
            Assert.AreEqual(256, dsaKey.Q.BitLength);

            var digitalSignature = new DsaDigitalSignature(dsaKey);

            byte[] signedBytes = digitalSignature.Sign(data);

            byte[] expectedSignedBytes = new byte[]
            {
                // echo -n 'hello world' | openssl dgst -sha1 -sign Key.DSA.txt -out test.signed
                0x30, 0x44, 0x02, 0x20, 0x71, 0xf2, 0xe1, 0x88, 0xbf, 0x31, 0xc2, 0xbc, 0x22, 0xc7, 0x27, 0x1a,
                0xfe, 0x73, 0x6a, 0x16, 0xb1, 0x87, 0xf9, 0x7c, 0x7b, 0x45, 0x85, 0xae, 0xde, 0xcc, 0xed, 0x3e,
                0x99, 0x04, 0x09, 0xfd, 0x02, 0x20, 0x32, 0x29, 0x81, 0xd6, 0x4d, 0xd7, 0xb0, 0x10, 0x76, 0x42,
                0x0f, 0x92, 0x7e, 0x16, 0x7d, 0xf3, 0xc6, 0x20, 0x11, 0x55, 0x7a, 0x14, 0x07, 0xba, 0x63, 0x34,
                0x2d, 0x3d, 0xfe, 0xb8, 0xad, 0xa2
            };

            CollectionAssert.AreEqual(expectedSignedBytes, signedBytes);

            Assert.IsTrue(digitalSignature.Verify(data, signedBytes));
        }

        [TestMethod]
        public void SignatureDoesNotTruncateLeadingZeroes()
        {
            byte[] data = { 0x6f, 0x90, 0x04, 0xce, 0x4b };

            DsaKey dsaKey = GetDsaKey("Key.DSA.txt");

            var digitalSignature = new DsaDigitalSignature(dsaKey);

            byte[] signedBytes = digitalSignature.Sign(data);

            CollectionAssert.AreEqual(new byte[]
            {
                0x00, 0x9a, 0xaa, 0x8f, 0xd6, 0x0a, 0x10, 0xa3, 0x8b, 0x02, 0xfd, 0x16, 0x27, 0xce, 0x08, 0xa1,
                0x70, 0xc5, 0x80, 0x78, 0x00, 0x53, 0x09, 0x27, 0x6e, 0x23, 0xcd, 0x77, 0xe2, 0x3b, 0xa1, 0x43,
                0x61, 0x2f, 0x7f, 0x6f, 0x69, 0x98, 0x79, 0xf5, 0xaf, 0xac, 0x43, 0xdc, 0xea, 0x30, 0x06, 0xbb,
                0x0e, 0xa3, 0xa0, 0xd9, 0x08, 0x50, 0x9b, 0x7b, 0x31, 0x5c, 0x57, 0x01, 0x57, 0xd7, 0xb3, 0xa2,
            }, signedBytes);

            Assert.IsTrue(digitalSignature.Verify(data, signedBytes));
        }

        private static DsaKey GetDsaKey(string fileName, string passPhrase = null)
        {
            using (var stream = GetData(fileName))
            {
                return (DsaKey)new PrivateKeyFile(stream, passPhrase).Key;
            }
        }
    }
}
