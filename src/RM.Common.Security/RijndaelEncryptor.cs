using System.Security.Cryptography;

namespace RM.Common.Security
{
    /// <summary>Represents a Rijndael encryptor.</summary>
    public sealed class RijndaelEncryptor : IEncryptor
    {
        private readonly SymmetricAlgorithm _rijndael = new RijndaelManaged();

        private readonly byte[] _key;
        private readonly byte[] _iv;

        /// <summary>
        /// Creates a new instance of the <see cref="RijndaelEncryptor" /> class.
        /// </summary>
        /// <param name="pasword">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The number of encryption iterations.</param>
        public RijndaelEncryptor(string pasword, Salt salt, int iterations)
        {
            using (var hasher = new Rfc2898DeriveBytes(pasword, salt, iterations))
            {
                _key = hasher.GetBytes(32);
                _iv = hasher.GetBytes(16);
            }
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] data)
        {
            using (var encryptor = _rijndael.CreateEncryptor(_key, _iv))
                return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <inheritdoc />
        public byte[] Decrypt(byte[] data)
        {
            using (var decryptor = _rijndael.CreateDecryptor(_key, _iv))
                return decryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
