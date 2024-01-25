#nullable enable
using System;
using System.Security.Cryptography;

using Renci.SshNet.Common;
using Renci.SshNet.Security.Cryptography;

namespace Renci.SshNet
{
    /// <summary>
    /// Serializes messages to binary packets using the Encrypt-then-MAC (etm) ordering
    /// as described in https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL#rev1.18.
    /// </summary>
    public class EncryptThenMacPacketEncryptor : PacketEncryptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptThenMacPacketEncryptor"/> class.
        /// </summary>
        /// <param name="cipher">The cipher to use for encrypting the payload.</param>
        /// <param name="mac">The message authentication algorithm to use.</param>
        public EncryptThenMacPacketEncryptor(Cipher? cipher, HashAlgorithm? mac)
            : base(cipher, mac)
        {
        }

        /// <inheritdoc/>
        public override byte[] Encrypt(byte[] packetData)
        {
            // Read out the packet_sequence_number and the packet_length.
            // These should not be encrypted, and the encryption returns a new array,
            // so we do a bit of a dance. As an optimisation, we should allow encrypting
            // into the same buffer.
            var sequenceNumberAndPacketLength = Pack.BigEndianToUInt64(packetData);

            // Encrypt packet data
            if (Cipher != null)
            {
                packetData = Cipher.Encrypt(packetData, 0, packetData.Length);
            }

            Pack.UInt64ToBigEndian(sequenceNumberAndPacketLength, packetData);

            if (Mac != null)
            {
                var hash = Mac.ComputeHash(packetData);

                var data = new byte[packetData.Length - 4 + hash.Length]; // -4 because we do not send the sequence_number.
                Buffer.BlockCopy(packetData, 4, data, 0, packetData.Length - 4);
                Buffer.BlockCopy(hash, 0, data, packetData.Length - 4, hash.Length);
                return data;
            }
            else
            {
                var data = new byte[packetData.Length - 4];
                Buffer.BlockCopy(packetData, 4, data, 0, packetData.Length - 4);
                return data;
            }
        }
    }
}
