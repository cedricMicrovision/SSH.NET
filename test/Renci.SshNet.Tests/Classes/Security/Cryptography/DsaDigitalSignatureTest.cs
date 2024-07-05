using System.IO;
using System.Text;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using Renci.SshNet.Common;
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
        public void Verify()
        {
            byte[] data = Encoding.UTF8.GetBytes("hello world");

            DsaKey dsaKey = GetDsaKey("Key.DSA.txt");

            Assert.AreEqual(1024, dsaKey.P.BitLength);
            Assert.AreEqual(160, dsaKey.Q.BitLength);

            var digitalSignature = new DsaDigitalSignature(dsaKey);

            // We can't compare signatures because they have a source of randomness

            _ = digitalSignature.Sign(data); // Does not throw

            byte[] signatureToVerify = new byte[]
            {
                // echo -n 'hello world' | openssl dgst -sha1 -sign Key.DSA.txt -out test.signed
                0x30, 0x2c, 0x02, 0x14, 0x77, 0x1c, 0x79, 0x08, 0xf2, 0xd7, 0x6f, 0x32, 0x4e, 0x76, 0x98, 0x20,
                0x5e, 0x04, 0x45, 0xe0, 0xb6, 0x28, 0xf3, 0xfa, 0x02, 0x14, 0x6a, 0x67, 0xba, 0x22, 0x45, 0xab,
                0x5c, 0x7d, 0x43, 0xf5, 0xa2, 0x36, 0x10, 0x5f, 0x90, 0x99, 0x30, 0x32, 0x08, 0x94
            };

            Assert.IsTrue(digitalSignature.Verify(data, signatureToVerify));
        }

        [TestMethod]
        public void Sign_QLengthNot160_ThrowsSshException()
        {
            byte[] data = Encoding.UTF8.GetBytes("hello world");

            var keyString = """
            -----BEGIN DSA PRIVATE KEY-----
            MIIE1QIBAAKCAYEAtAdLEc+EX07PpPJq1wPcFo17xJA7qaYA/Ef+9PNpde3O6ZFu
            cDZU65xg/wIu+e5FAj1tLtwA3V3hAX3C0hj5Tse8I84nog7Jo2b0c/MUGEYyAsop
            pEyPTshn44+lNyM3e9OONK+kP9ZtE9Bj6/f7GkF2/3s7VQ0oLBFWULiHGKWEBVwn
            EsuNq//5RCSs1Tw2VSLpnFC9EM18pqdWUkVmN0xtvRx0RyNhtChU0Qf19e1dpY8r
            diJXLLuKXxVu5MkkeLGPsT5znK4TI28At9xoeQnXhcgD/ddIvs24nVujhfwUN8aw
            LureThWDAyFgtkEuxyCAGk0OwjpBqKHeGwOvtrwSMWzOxcaX1eSE6LbI284jWPRZ
            h8EtutF+yme1x/JFbYCWQwLjFlcrsBSWaIFjUJBYozJe9vwBB4SdIMfkj//26Clm
            tiGI08RAfMWKDO/1NHI/LR+Z1g3RrGWwO/fIXNsR6gSp5uV4Wxm/Fs7c0Re458AH
            VMn1e8faEwrs3O1DAiEAlyKR5Pw7z/+OmBqpXyBYPAA9bDxiXP0iqRhKCdXKNekC
            ggGACj7sSYBFWEihpx7JIwfEnKCd8YTBfCLWrs5ZwrhND4PIgMg9rLxQc76kBYuq
            nnb0wxwR3RmVyIHB8KD7c/AhE5tCO5d2VayVr/ATHtWyTGnejT3N3NYtHlDffJLQ
            bCgHVnWZK9Mvr+H4UaN0bBqOSvSYUsHHAa9OKHWaIz4XLqBmbZwsw+FBiVm1l4Fo
            n5lSiztT7qzLraL2VD8JPnA6Sp9DUNp24F8H35eUMann9jdO7UD02q2HFDpUZmhQ
            8xTO3ONiHLbjFd7nLKILyQ/pv4YfupJdItmqvlIwygN6AzwM3Pa25RTX7PyS16CX
            RdMGsnFIrVruu431qIouut54bSVdLm2n5sHnpVy2AoeXSzOvDs8S6sq+9aXhfT6F
            23RdpHXa3HnGXbg/as4QXuXUzpnDZwRD6bZ+0ec9G39IgU4hAa0AUMtZzB3ODjvT
            8qdacAfvjj1doQCQMufb+GfH5l2mOFV/+MmRn0KYVWUfdI+iSnyi4HM/GwrITYyw
            8wNNAoIBgAKxFZB3JI/Z9LuJZhdfrnY+MZQa8lxO/Z4xfo7goJVMuGHuxhFFDTXL
            xe17P2pojyzlq9IoUpPEeeBFq1/6IGzE7RejSs1vqcmIXDCC7Xvnqxi9AUjBmoVF
            xjWhJcSmwPcOI3Y/mflA2nElfMrPvVw4MtoY+P/rpWieujNfbOoBplDDKCxcNZE5
            P3BedQQxPKk4C9gi8KcrpJIsevDCJxoGXyuAAI1oGkJY6hvCiANX96KqLSeuyvHz
            LM7VRaIteabg9Mp26e+JAhAxKlH6Xbh9p1sA72+A5x7xiAtry9UKq6s1/Fu0y4xD
            ZAxTgEvHOiDwDgNCXMTJQPLBCUn1ACXMIw0nL0+bb2HHRCjRB667T340JdMYyFSL
            RX6foxC9tX8F0JhQ3JbRpYHWs09saUv02+avuqIAQC0n1ILY6huVzFc6ibHeNXa8
            kZTQzJt0Y5/dsRxn3x5tHDKr4GRwAcurKr+gItdN03OAcKDVufz9LmjPH2EkLdn9
            olINq/lJqAIgSAIUJSj/fRYso/bxFUJJ0xaK08u5HusXw+hCWcCqQGU=
            -----END DSA PRIVATE KEY-----
            """;

            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(keyString));

            DsaKey dsaKey = (DsaKey)new PrivateKeyFile(stream).Key;

            Assert.AreEqual(3072, dsaKey.P.BitLength);
            Assert.AreEqual(256, dsaKey.Q.BitLength);

            var digitalSignature = new DsaDigitalSignature(dsaKey);

            Assert.ThrowsException<SshException>(() => digitalSignature.Sign(data));
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
