using System.Diagnostics;
#if NET
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#endif
#if NET7_0_OR_GREATER
using System.Runtime.Intrinsics;
#endif

using Renci.SshNet.Common;

namespace Renci.SshNet.Security.Cryptography.Ciphers
{
    /// <summary>
    /// Base class for cipher mode implementations.
    /// </summary>
    public abstract class CipherMode
    {
#pragma warning disable SA1401 // Fields should be private
#pragma warning disable SA1306 // Field names should begin with lower-case letter
        /// <summary>
        /// Gets the cipher.
        /// </summary>
        protected BlockCipher Cipher;

        /// <summary>
        /// Gets the IV vector.
        /// </summary>
        protected byte[] IV;

        /// <summary>
        /// Holds block size of the cipher.
        /// </summary>
        protected int _blockSize;
#pragma warning restore SA1306 // Field names should begin with lower-case letter
#pragma warning restore SA1401 // Fields should be private

        /// <summary>
        /// Initializes a new instance of the <see cref="CipherMode"/> class.
        /// </summary>
        /// <param name="iv">The iv.</param>
        protected CipherMode(byte[] iv)
        {
            IV = iv;
        }

        /// <summary>
        /// Initializes the specified cipher mode.
        /// </summary>
        /// <param name="cipher">The cipher.</param>
        internal void Init(BlockCipher cipher)
        {
            Cipher = cipher;
            _blockSize = cipher.BlockSize;
            IV = IV.Take(_blockSize);
        }

        /// <summary>
        /// Encrypts the specified region of the input byte array and copies the encrypted data to the specified region of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input data to encrypt.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">The output to which to write encrypted data.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        /// <returns>
        /// The number of bytes encrypted.
        /// </returns>
        public abstract int EncryptBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

        /// <summary>
        /// Decrypts the specified region of the input byte array and copies the decrypted data to the specified region of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input data to decrypt.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">The output to which to write decrypted data.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        /// <returns>
        /// The number of bytes decrypted.
        /// </returns>
        public abstract int DecryptBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

#pragma warning disable IDE0007 // Use implicit type
#pragma warning disable SA1137 // Elements should have the same indentation
        private protected static void Xor(
            int blockSize,
            byte[] outputBuffer,
            int outputOffset,
            byte[] leftBuffer,
            int leftOffset,
            byte[] rightBuffer,
            int rightOffset)
        {
            Debug.Assert(blockSize > 0);
            Debug.Assert((uint)leftOffset < leftBuffer.Length);
            Debug.Assert((uint)(leftOffset + blockSize) <= leftBuffer.Length);

            Debug.Assert((uint)rightOffset < rightBuffer.Length);
            Debug.Assert((uint)(rightOffset + blockSize) <= rightBuffer.Length);

#if NET
            if (blockSize == 16)
            {
#if NET7_0_OR_GREATER

                Vector128<byte> left = Vector128.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(leftBuffer), (nuint) leftOffset);
                Vector128<byte> right = Vector128.LoadUnsafe(ref MemoryMarshal.GetArrayDataReference(rightBuffer), (nuint) rightOffset);
                ref byte output = ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(outputBuffer), (nuint) outputOffset);

                (left ^ right).StoreUnsafe(ref output);

#else // !NET7_0_OR_GREATER

                ref ulong left = ref Unsafe.Add(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetArrayDataReference(leftBuffer)), (nuint) leftOffset);
                ref ulong right = ref Unsafe.Add(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetArrayDataReference(rightBuffer)), (nuint) rightOffset);
                ref ulong output = ref Unsafe.Add(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetArrayDataReference(outputBuffer)), (nuint) outputOffset);

                output = left ^ right;

                left = Unsafe.Add(ref left, 8);
                right = Unsafe.Add(ref right, 8);
                output = Unsafe.Add(ref output, 8);

                output = left ^ right;

#endif // !NET7_0_OR_GREATER
            }
            else if (blockSize == 8)
            {
                ref ulong left = ref Unsafe.Add(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetArrayDataReference(leftBuffer)), (nuint) leftOffset);
                ref ulong right = ref Unsafe.Add(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetArrayDataReference(rightBuffer)), (nuint) rightOffset);
                ref ulong output = ref Unsafe.Add(ref Unsafe.As<byte, ulong>(ref MemoryMarshal.GetArrayDataReference(outputBuffer)), (nuint) outputOffset);

                output = left ^ right;
            }
            else
            {
#endif // NET

                for (var i = 0; i < blockSize; i++)
                {
                    outputBuffer[outputOffset + i] = (byte) (leftBuffer[leftOffset + i] ^ rightBuffer[rightOffset + i]);
                }

#if NET
            }
#endif // NET

        }
#pragma warning restore SA1137 // Elements should have the same indentation
#pragma warning restore IDE0007 // Use implicit type

    }
}
