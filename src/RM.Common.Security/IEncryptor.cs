namespace RM.Common.Security
{
    /// <summary>Represents a common interface for encryptor.</summary>
    public interface IEncryptor
    {
        /// <summary>
        /// Encrypts specified <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>Encrypted data.</returns>
        byte[] Encrypt(byte[] data);

        /// <summary>
        /// Decrypts specified <paramref name="data" />.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <returns>Decrypted data.</returns>
        byte[] Decrypt(byte[] data);
    }
}
