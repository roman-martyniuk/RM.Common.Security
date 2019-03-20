using System;
using System.Security.Cryptography;
using RM.Common.Security.Utils;

namespace RM.Common.Security
{
    /// <summary>
    /// Represents the crypto secure salt for hashing.
    /// </summary>
    public sealed class Salt
    {
        private const byte MIN_SALT_LENGTH = 8;
        private const byte RECOMMENDED_SALT_LENGTH = 32;
        private const byte MAX_SALT_LENGTH = 64;

        private readonly byte[] _salt;
        private readonly string _base64EncodedSalt;

        /// <summary>
        /// Creates a new instance of the <see cref="Salt" /> class with the crypto secure randomly generated salt with the default recommended length of 32 bytes (256 bits).
        /// </summary>
        public Salt() : this(RECOMMENDED_SALT_LENGTH) { }

        /// <summary>
        /// Creates a new instance of the <see cref="Salt" /> class with the crypto secure randomly generated salt with the specified <paramref name="length" />.
        /// </summary>
        /// <param name="length">The salt length in bytes. Min value is 8. Max value is 64.</param>
        public Salt(int length)
        {
            if (length < MIN_SALT_LENGTH || length > MAX_SALT_LENGTH) throw new ArgumentOutOfRangeException(nameof(length));

            _salt = new byte[length];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetNonZeroBytes(_salt);

            _base64EncodedSalt = _salt.ToBase64String();
        }

        /// <summary>
        /// Create a new instance of the <see cref="Salt" /> class based on the byte array.
        /// </summary>
        /// <param name="salt">The salt as byte array. Min length is 8 bytes and max length is 64.</param>
        public Salt(byte[] salt)
        {
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (salt.Length < MIN_SALT_LENGTH || salt.Length > MAX_SALT_LENGTH) throw new ArgumentOutOfRangeException(nameof(salt));

            _salt = salt;
            _base64EncodedSalt = _salt.ToBase64String();
        }

        /// <summary>
        /// Decodes the salt value from the Base64 encoded string.
        /// </summary>
        /// <param name="base64EncodedSalt">The salt string to decode.</param>
        public Salt(string base64EncodedSalt)
        {
            if (string.IsNullOrWhiteSpace(base64EncodedSalt)) throw new ArgumentException("Salt string can not be null or empty or contain only white space character", nameof(base64EncodedSalt));
            if (base64EncodedSalt.Length < MIN_SALT_LENGTH) throw new ArgumentException("Salt string is too short", nameof(base64EncodedSalt));

            _salt = base64EncodedSalt.FromBase64String();

            if (_salt.Length < MIN_SALT_LENGTH) throw new ArgumentException("Decoded salt is too short (< 8 bytes).", nameof(base64EncodedSalt));
            if (_salt.Length > MAX_SALT_LENGTH) throw new ArgumentException("Decoded salt is too long (> 64 bytes).", nameof(base64EncodedSalt));
            
            _base64EncodedSalt = base64EncodedSalt;
        }

        /// <summary>
        /// Returns the byte array representations of the current salt.
        /// </summary>
        public byte[] ToByteArray() => _salt;

        /// <summary>
        /// Returns the string representation (Base64) of the current salt.
        /// </summary>
        public string ToBase64String() => _base64EncodedSalt;

        /// <summary>
        /// An implicit convertion to <see cref="T:System.String" />.
        /// </summary>
        /// <param name="salt">The salt to convert.</param>
        /// <returns>Converted salt.</returns>
        public static implicit operator string(Salt salt) => salt?._base64EncodedSalt;

        /// <summary>An implicit convertion to byte array.</summary>
        /// <param name="salt">The salt to convert.</param>
        /// <returns>Converted salt.</returns>
        public static implicit operator byte[] (Salt salt) => salt?._salt;

        /// <inheritdoc />
        public override string ToString() => _base64EncodedSalt;
    }
}
