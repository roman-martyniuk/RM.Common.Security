namespace RM.Common.Security
{
    /// <summary>Represents a common interface for hashing algorithms.</summary>
    public interface IHasher
    {
        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <param name="data">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        /// <exception cref="T:System.ArgumentNullException">data is null.</exception>
        byte[] ComputeHash(byte[] data);

        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <param name="data">The input to compute the hash code for.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <returns>The computed hash code.</returns>
        /// <exception cref="T:System.ArgumentNullException">data is null.</exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException">The number of iterations is less than 1. </exception>
        byte[] ComputeHash(byte[] data, int iterations);

        /// <summary>
        /// Computes the hash value for the specified string.
        /// </summary>
        /// <param name="data">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        /// <exception cref="T:System.ArgumentNullException">data is null.</exception>
        string ComputeHash(string data);

        /// <summary>
        /// Computes the hash value for the specified string.
        /// </summary>
        /// <param name="data">The input to compute the hash code for.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <returns>The computed hash code.</returns>
        /// <exception cref="T:System.ArgumentNullException">data is null.</exception>
        /// <exception cref="T:System.ArgumentOutOfRangeException">The number of iterations is less than 1. </exception>
        string ComputeHash(string data, int iterations);
    }
}
