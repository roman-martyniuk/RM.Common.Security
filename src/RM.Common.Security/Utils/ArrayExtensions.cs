using System;

namespace RM.Common.Security.Utils
{
    internal static class ArrayExtensions
    {
        /// <summary>
        /// Clones the specified byte <paramref name="array" />.
        /// </summary>
        /// <param name="array">The byte array to clone.</param>
        /// <returns>Returns the cloned byte array.</returns>
        public static byte[] CloneArray(this byte[] array)
        {
            if (array == null) throw new ArgumentNullException(nameof (array));

            var result = new byte[array.Length];
            Buffer.BlockCopy(array, 0, result, result.Length, array.Length);
            return result;
        }

        public static string ToBase64String(this byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof (data));

            return Convert.ToBase64String(data);
        }

        public static T[] Combine<T>(this T[] first, T[] second)
        {
            if (first == null) throw new ArgumentNullException(nameof (first));
            if (second == null) throw new ArgumentNullException(nameof (second));

            var result = new T[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
            return result;
        }

        public static T[] Combine<T>(this T[] first, T[] second, T[] third)
        {
            if (first == null) throw new ArgumentNullException(nameof (first));
            if (second == null) throw new ArgumentNullException(nameof (second));
            if (third == null) throw new ArgumentNullException(nameof (third));

            var result = new T[first.Length + second.Length + third.Length];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
            Buffer.BlockCopy(third, 0, result, first.Length + second.Length, third.Length);
            return result;
        }

        public static T[] Shuffle<T>(this T[] src)
        {
            if (src == null) throw new ArgumentNullException(nameof (src));

            var rnd = new Random();
            for (var i = 0; i < src.Length; ++i)
            {
                var randomIndex = rnd.Next(src.Length);
                src.Swap(i, randomIndex);
            }
            return src;
        }

        public static void Swap<T>(this T[] src, int index1, int index2)
        {
            if (src == null) throw new ArgumentNullException(nameof (src));
            if (index1 == index2) return;

            var buf = src[index1];
            src[index1] = src[index2];
            src[index2] = buf;
        }

        /// <summary>
        /// Converts specified <paramref name="data" /> to hex string.
        /// </summary>
        /// <param name="data">The data to convert.</param>
        /// <returns>Hex string.</returns>
        public static string ToHexString(this byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof (data));
            
            return data.Length != 0 ? BitConverter.ToString(data).Replace("-", "") : "";
        }
    }
}