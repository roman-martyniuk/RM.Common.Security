using System;
using System.Diagnostics;
using System.Linq;
using RM.Common.Security.Utils;

namespace RM.Common.Security
{
    /// <summary>Represents a SHA512 password hasher.</summary>
    public sealed class PasswordHash
    {
        private readonly byte[] _hash;
        private readonly string _base64EncodedHash;

        /// <summary>
        /// Creates a new instance of the <see cref="PasswordHash" /> class.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="staticSalt">The static salt.</param>
        public PasswordHash(string password, Salt staticSalt = null)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));

            _hash = GenerateHash(password, new Salt(), CryptoRandom.Next(8397, 11893), staticSalt);
            _base64EncodedHash = _hash.ToBase64String();
        }

        /// <summary>
        /// Returns the byte array representations of the current password hash.
        /// </summary>
        public byte[] ToByteArray() => _hash;

        /// <summary>
        /// Returns the string representation (Base64) of the current password hash.
        /// </summary>
        public string ToBase64String() => _base64EncodedHash;

        private static byte[] GenerateHash(string password, byte[] dynamicSalt, int iterations, byte[] staticSalt)
        {
            var hash = password.ToByteArray().Combine(dynamicSalt).ComputeHash(iterations);
            if (staticSalt != null) hash = hash.Combine(staticSalt).ComputeHash();
            return hash.Combine(BitConverter.GetBytes(iterations), dynamicSalt);
        }

        /// <summary>
        /// Checks whether specified <paramref name="password" /> is valid.
        /// </summary>
        /// <param name="base64EncodedPasswordHash">The Base64 encoded password hash to check.</param>
        /// <param name="password">The password to check.</param>
        /// <param name="staticSalt">The static salt.</param>
        public static bool IsValid(string base64EncodedPasswordHash, string password, Salt staticSalt = null)
        {
            if (base64EncodedPasswordHash == null) throw new ArgumentNullException(nameof(base64EncodedPasswordHash));

            return IsValid(base64EncodedPasswordHash.FromBase64String(), password, staticSalt);
        }

        /// <summary>
        /// Checks whether specified <paramref name="password" /> is valid.
        /// </summary>
        /// <param name="passwordHash">The password hash to check.</param>
        /// <param name="password">The password to check.</param>
        /// <param name="staticSalt">The static salt.</param>
        public static bool IsValid(byte[] passwordHash, string password, Salt staticSalt = null)
        {
            if (passwordHash == null) throw new ArgumentNullException(nameof(passwordHash));
            if (password == null) throw new ArgumentNullException(nameof(password));

            
            try
            {
                if (passwordHash.Length <= 76) return false; //76 = 64 (SHA-512 hash) + 4 (iterations int value) + 8 (min salt length)

                var hash = new byte[64];
                Buffer.BlockCopy(passwordHash, 0, hash, 0, 64);

                var iterations = BitConverter.ToInt32(passwordHash, 64);

                var dynamicSalt = new byte[passwordHash.Length - 68];
                Buffer.BlockCopy(passwordHash, 68, dynamicSalt, 0, passwordHash.Length - 68);
                
                var generatedHash = GenerateHash(password, dynamicSalt, iterations, staticSalt);
                return generatedHash.SequenceEqual(passwordHash);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                return false;
            }
        }

        /// <summary>
        /// An implicit convertion to <see cref="string" />.
        /// </summary>
        public static implicit operator string(PasswordHash passwordHash) => passwordHash?._base64EncodedHash;

        /// <summary>An implicit convertion to byte array.</summary>
        public static implicit operator byte[] (PasswordHash passwordHash) => passwordHash?._hash;

        /// <inheritdoc />
        public override string ToString() => _base64EncodedHash;
    }
}
