using System.Security.Cryptography;
using RM.Common.Security.Utils;

namespace RM.Common.Security
{
    /// <summary>Represents a factory of hashing algorithms</summary>
    public static class HashersFactory
    {
        /// <summary>The SHA1 hash algorithm.</summary>
        public static IHasher SHA1 { get; } = new GenericHasher<SHA1CryptoServiceProvider>(() => new SHA1CryptoServiceProvider());

        /// <summary>The MD5 hash algorithm.</summary>
        public static IHasher MD5 { get; } = new GenericHasher<MD5CryptoServiceProvider>(() => new MD5CryptoServiceProvider());

        /// <summary>The SHA256 hash algorithm.</summary>
        public static IHasher SHA256 { get; } = new GenericHasher<SHA256Managed>(() => new SHA256Managed());

        /// <summary>The SHA384 hash algorithm.</summary>
        public static IHasher SHA384 { get; } = new GenericHasher<SHA384Managed>(() => new SHA384Managed());

        /// <summary>The SHA512 hash algorithm.</summary>
        public static IHasher SHA512 { get; } = new GenericHasher<SHA512Managed>(() => new SHA512Managed());
    }
}
