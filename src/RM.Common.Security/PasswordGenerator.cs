using System;
using RM.Common.Security.Utils;

namespace RM.Common.Security
{
    /// <summary>
    /// Generates crypto-random passwords and validates that they meet the rules passed in.
    /// </summary>
    public sealed class PasswordGenerator
    {
        /// <summary>The min password length.</summary>
        public int MinLength { get; }

        /// <summary>The max password length.</summary>
        public int MaxLength { get; }

        /// <summary>The min number of lowercase letters.</summary>
        public int MinLower { get; }

        /// <summary>The min number of uppercase letters.</summary>
        public int MinUpper { get; }

        /// <summary>The min number of digits.</summary>
        public int MinNumeric { get; }

        /// <summary>The min number of symbols.</summary>
        public int MinSymbols { get; }

        private readonly string _chars;

        private readonly int _minimumNumberOfChars;
        // M="ahJYyu73&&*kjd(" I="", P="1234356"
        // Ranges not using confusing characters
        private const string UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";// "IO" characters are excluded from range
        private const string LOWER = "abcdefghjkmnpqrstuvwxyz"; // "ilo" characters are excluded from range
        private const string NUMBERS = "23456789"; // "01" characters are excluded from range
        private const string SYMBOLS = "!@#$%^&?*()-_+={}[]<>"; // confusing symbols are excluded from range

        /// <summary>
        /// Creates a new instance of the <see cref="T:RM.Common.Security.PasswordGenerator" /> class.
        /// </summary>
        /// <param name="minLength">The min password length.</param>
        /// <param name="maxLength">The max password length.</param>
        /// <param name="minLower">The min number of lowercase letters.</param>
        /// <param name="minUpper">The min number of uppercase letters.</param>
        /// <param name="minNumeric">The min number of digits.</param>
        /// <param name="minSymbols">The min number of symbols.</param>
        public PasswordGenerator(int minLength = 8, int maxLength = 15, int minLower = 1, int minUpper = 1, int minNumeric = 1, int minSymbols = 1)
        {
            if (minLength < 1) throw new ArgumentException("The minimumlength is smaller than 1.", nameof(minLength));
            if (minLength > maxLength) throw new ArgumentException("The minimumLength is bigger than the maximum length.", nameof(minLength));
            if (minLower < 0) throw new ArgumentException("The minimumLowerCase is smaller than 0.", nameof(minLower));
            if (minUpper < 0) throw new ArgumentException("The minimumUpperCase is smaller than 0.", nameof(minUpper));
            if (minNumeric < 0) throw new ArgumentException("The minimumNumeric is smaller than 0.", nameof(minNumeric));
            if (minSymbols < 0) throw new ArgumentException("The minimumSpecial is smaller than 0.", nameof(minSymbols));

            _minimumNumberOfChars = minLower + minUpper + minNumeric + minSymbols;

            if (minLength < _minimumNumberOfChars) throw new ArgumentException("The minimum length ot the password is smaller than the sum of the minimum characters of all catagories.", nameof(maxLength));

            MinLength = minLength;
            MaxLength = maxLength;

            MinLower = minLower;
            MinUpper = minUpper;
            MinNumeric = minNumeric;
            MinSymbols = minSymbols;

            _chars =
                OnlyIfOneCharIsRequired(minLower, LOWER) +
                OnlyIfOneCharIsRequired(minUpper, UPPER) +
                OnlyIfOneCharIsRequired(minNumeric, NUMBERS) +
                OnlyIfOneCharIsRequired(minSymbols, SYMBOLS);
        }

        private string OnlyIfOneCharIsRequired(int minimum, string allChars)
        {
            return minimum > 0 || _minimumNumberOfChars == 0 ? allChars : string.Empty;
        }

        /// <summary>
        /// Generates password according to rules specified in constructor.
        /// </summary>
        /// <returns>Generated random password.</returns>
        public string Generate()
        {
            var password = new char[CryptoRandom.Next(MinLength, MaxLength)];

            Generate(password, 0, MinLower, LOWER);
            Generate(password, MinLower, MinUpper, UPPER);
            Generate(password, MinLower + MinUpper, MinNumeric, NUMBERS);
            Generate(password, MinLower + MinUpper + MinNumeric, MinSymbols, SYMBOLS);
            Generate(password, MinLower + MinUpper + MinNumeric + MinSymbols, _chars);

            // Shuffle the result so the order of the characters are unpredictable
            return new string(password.Shuffle());
        }

        private static void Generate(char[] src, int startIndex, string charset)
        {
            Generate(src, startIndex, src.Length - startIndex, charset);
        }

        private static void Generate(char[] src, int startIndex, int lenght, string charset)
        {
            var n = startIndex + lenght;
            for (var i = startIndex; i < n; i++) src[i] = charset[CryptoRandom.Next(charset.Length)];
        }
    }
}