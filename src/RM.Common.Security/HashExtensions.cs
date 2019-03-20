using System;

namespace RM.Common.Security
{
    /// <summary>Represents extension methods for hashing.</summary>
    public static class HashExtensions
    {
        /// <summary>
        /// Computes hash of the specified <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="hashType">The type of hash.</param>
        /// <returns>Computed hash.</returns>
        public static byte[] ComputeHash(this byte[] data, HashType hashType = HashType.SHA512)
        {
            return GetHasher(hashType).ComputeHash(data);
        }

        /// <summary>
        /// Computes hash of the specified <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="iterations">The number of hash iterations.</param>
        /// <param name="hashType">The type of hash.</param>
        /// <returns>Computed hash.</returns>
        public static byte[] ComputeHash(this byte[] data, int iterations, HashType hashType = HashType.SHA512)
        {
            return GetHasher(hashType).ComputeHash(data, iterations);
        }

        /// <summary>
        /// Computes hash of the specified <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="hashType">The type of hash.</param>
        /// <returns>Computed hash.</returns>
        public static string ComputeHash(this string data, HashType hashType = HashType.SHA512)
        {
            return GetHasher(hashType).ComputeHash(data);
        }

        /// <summary>
        /// Computes hash of the specified <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="iterations">The number of hash iterations.</param>
        /// <param name="hashType">The type of hash.</param>
        /// <returns>Computed hash.</returns>
        public static string ComputeHash(this string data, int iterations, HashType hashType = HashType.SHA512)
        {
            return GetHasher(hashType).ComputeHash(data, iterations);
        }

        private static IHasher GetHasher(HashType hashType)
        {
            switch (hashType)
            {
                case HashType.SHA512: return HashersFactory.SHA512;
                case HashType.SHA384: return HashersFactory.SHA384;
                case HashType.SHA256: return HashersFactory.SHA256;
                case HashType.MD5: return HashersFactory.MD5;
                case HashType.SHA1: return HashersFactory.SHA1;
                default: throw new ArgumentOutOfRangeException(nameof(hashType));
            }
        }
    }
}
