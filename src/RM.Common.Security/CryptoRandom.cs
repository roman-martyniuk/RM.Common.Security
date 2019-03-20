using System;
using System.Security.Cryptography;

namespace RM.Common.Security
{
    /// <summary>
    /// Represents a crypto secure random number generator.
    /// </summary>
    public static class CryptoRandom
    {
        /// <summary>
        /// Returns a nonnegative random number.
        /// </summary>
        /// <returns>A 32-bit signed integer greater than or equal to zero and less than <see cref="int.MaxValue"/>.</returns>
        public static int Next()
        {
            var data = new byte[4];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(data);

            return (BitConverter.ToInt32(data, 0) & int.MaxValue) % int.MaxValue;
        }

        /// <summary>
        /// Returns a nonnegative random number less than the specified maximum.
        /// </summary>
        /// <param name="maxValue">The exclusive upper bound of the random number to be generated. <paramref name="maxValue" /> must be greater than or equal to zero.</param>
        /// <returns>A 32-bit signed integer greater than or equal to zero, and less than <code>maxValue</code>;
        /// that is, the range of return values ordinarily includes zero but not <paramref name="maxValue" />.
        /// However, if <paramref name="maxValue" /> equals zero, <paramref name="maxValue" /> is returned.</returns>
        public static int Next(int maxValue)
        {
            if (maxValue < 0) throw new ArgumentOutOfRangeException(nameof(maxValue));

            return Next() % maxValue;
        }

        /// <summary>Returns a random number within a specified range.</summary>
        /// <param name="minValue">The inclusive lower bound of the random number returned.</param>
        /// <param name="maxValue">The exclusive upper bound of the random number returned. <paramref name="maxValue" /> must be greater than or equal to <paramref name="minValue" />.</param>
        /// <returns>A 32-bit signed integer greater than or equal to <paramref name="minValue" /> and less than <paramref name="maxValue" />; that is, the range of return values includes <paramref name="minValue" /> but not <paramref name="maxValue" />.
        /// If <paramref name="minValue" /> equals <paramref name="maxValue" />, minValue is returned.</returns>
        public static int Next(int minValue, int maxValue)
        {
            if (minValue > maxValue) throw new ArgumentOutOfRangeException(nameof(minValue));
            if (minValue == maxValue) return minValue;

            var diff = maxValue - minValue;
            return minValue + Next(diff);
        }

        /// <summary>
        /// Returns a random number between 0.0 and 1.0.
        /// </summary>
        /// <returns>A double-precision floating point number greater than or equal to 0.0, and less than 1.0.</returns>
        public static double NextDouble()
        {
            var data = new byte[8];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(data);

            var generatedDouble = Math.Abs(BitConverter.ToDouble(data, 0));
            return generatedDouble - Math.Truncate(generatedDouble);
        }

        /// <summary>
        /// Fills the elements of a specified array of bytes with random numbers.
        /// </summary>
        /// <param name="buffer">An array of bytes to contain random numbers.</param>
        public static void NextBytes(byte[] buffer)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));

            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(buffer);
        }
    }
}