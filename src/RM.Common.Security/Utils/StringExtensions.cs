using System;
using System.Text;

namespace RM.Common.Security.Utils
{
    internal static class StringExtensions
    {
        public static byte[] FromBase64String(this string str)
        {
            if (str == null) throw new ArgumentNullException(nameof(str));

            return Convert.FromBase64String(str);
        }

        public static byte[] ToByteArray(this string str)
        {
            if (str == null) throw new ArgumentNullException(nameof(str));

            return Encoding.Unicode.GetBytes(str);
        }
    }
}