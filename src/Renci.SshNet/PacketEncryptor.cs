#nullable enable
using System;
using System.Diagnostics;
using System.Security.Cryptography;

using Renci.SshNet.Security.Cryptography;

namespace Renci.SshNet
{
    /// <summary>
    /// Encrypts messages in the SSH binary packet format as specified
    /// in RFC 4253.
    /// </summary>
    public class PacketEncryptor : IPacketEncryptor
    {
        /// <inheritdoc/>
        public byte PaddingMultiplier { get; }

        /// <summary>
        /// Gets the cipher to use for encrypting the payload.
        /// </summary>
        protected Cipher? Cipher { get; }

        /// <summary>
        /// Gets the message authentication algorithm to use.
        /// </summary>
        protected HashAlgorithm? Mac { get; }

        private bool _disposedValue;

        /// <summary>
        /// Initializes a new instance of the <see cref="PacketEncryptor"/> class.
        /// </summary>
        /// <param name="cipher">The cipher to use for encrypting the payload.</param>
        /// <param name="mac">The message authentication algorithm to use.</param>
        public PacketEncryptor(Cipher? cipher, HashAlgorithm? mac)
        {
            Cipher = cipher;
            Mac = mac;
            PaddingMultiplier = cipher is null ? (byte)8 : Math.Max((byte)8, cipher.MinimumSize);
        }

        /// <inheritdoc/>
        public virtual byte[] Encrypt(byte[] packetData)
        {
            byte[]? hash = null;
            var packetDataOffset = 4; // first four bytes are reserved for outbound packet sequence

            if (Mac != null)
            {
                // calculate packet hash
                hash = Mac.ComputeHash(packetData);
            }

            // Encrypt packet data
            if (Cipher != null)
            {
                packetData = Cipher.Encrypt(packetData, packetDataOffset, packetData.Length - packetDataOffset);
                packetDataOffset = 0;
            }

            var packetLength = packetData.Length - packetDataOffset;
            if (hash is null)
            {
                if (packetDataOffset == 0)
                {
                    Debug.Assert(Cipher != null);
                    return packetData;
                }

                var data = new byte[packetLength];
                Buffer.BlockCopy(packetData, packetDataOffset, data, 0, packetLength);
                return data;
            }
            else
            {
                var data = new byte[packetLength + hash.Length];
                Buffer.BlockCopy(packetData, packetDataOffset, data, 0, packetLength);
                Buffer.BlockCopy(hash, 0, data, packetLength, hash.Length);
                return data;
            }
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><see langword="true"/> to release both managed and unmanaged resources; <see langword="false"/> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    if (Cipher is IDisposable disposableCipher)
                    {
                        disposableCipher.Dispose();
                    }

                    Mac?.Dispose();
                }

                _disposedValue = true;
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
