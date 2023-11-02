#if NETFRAMEWORK || NETSTANDARD2_0
using Renci.SshNet.Common;
#endif

namespace System.Numerics
{
    // Polyfills of methods on BigInteger for lower targets
    // (higher targets resolve to an instance method)
    internal static class Extensions
    {
#if NETFRAMEWORK || NETSTANDARD2_0
        public static byte[] ToByteArray(this BigInteger bigInt, bool isUnsigned = false, bool isBigEndian = false)
        {
            var data = bigInt.ToByteArray();

            if (isUnsigned && data[data.Length - 1] == 0)
            {
                data = data.Take(data.Length - 1);
            }

            return isBigEndian ? data.Reverse() : data;
        }
#endif

#if !NET6_0_OR_GREATER
        public static long GetBitLength(this BigInteger bigint)
        {
            // Taken from https://github.com/dotnet/runtime/issues/31308
            return (long) Math.Ceiling(BigInteger.Log(bigint.Sign < 0 ? -bigint : bigint + 1, 2));
        }
#endif
    }
}
