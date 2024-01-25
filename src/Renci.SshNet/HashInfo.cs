using System;
using System.Security.Cryptography;
using Renci.SshNet.Common;

namespace Renci.SshNet
{
    /// <summary>
    /// Holds information about key size and MAC to use.
    /// </summary>
    public class HashInfo
    {
        /// <summary>
        /// Gets the size of the key.
        /// </summary>
        /// <value>
        /// The size of the key.
        /// </value>
        public int KeySize { get; private set; }

        /// <summary>
        /// Gets the cipher.
        /// </summary>
        public Func<byte[], HashAlgorithm> HashAlgorithm { get; private set; }

        /// <summary>
        /// Gets a value indicating whether this MAC algorithm uses
        /// "encrypt then MAC" ordering (calculating the MAC over the packet
        /// ciphertext rather than the plaintext).
        /// </summary>
        public bool IsEncryptThenMac { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HashInfo"/> class.
        /// </summary>
        /// <param name="keySize">Size of the key.</param>
        /// <param name="hash">The hash algorithm to use for a given key.</param>
        /// <param name="isEncryptThenMac">Whether this MAC algorithm uses "encrypt then MAC" ordering.</param>
        public HashInfo(int keySize, Func<byte[], HashAlgorithm> hash, bool isEncryptThenMac = false)
        {
            KeySize = keySize;
            HashAlgorithm = key => hash(key.Take(KeySize / 8));
            IsEncryptThenMac = isEncryptThenMac;
        }
    }
}
