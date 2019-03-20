using System;
using System.Security.Cryptography;

namespace RM.Common.Security.Utils
{
    internal sealed class GenericHasher<T> : IHasher where T : HashAlgorithm, new()
    {
        private static readonly Func<T> DefaultInstanceCreator = () => new T();
        private readonly Func<T> _instanceCreator;

        internal GenericHasher()
        {
            _instanceCreator = DefaultInstanceCreator;
        }

        internal GenericHasher(Func<T> instanceCreator)
        {
            _instanceCreator = instanceCreator ?? DefaultInstanceCreator;
        }

        public byte[] ComputeHash(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            
            using (var alg = _instanceCreator())
                return alg.ComputeHash(data);
        }

        public byte[] ComputeHash(byte[] data, int iterations)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations), "The number of iterations is less than 1");

            using (var alg = _instanceCreator())
            {
                var result = alg.ComputeHash(data);
                for (var i = 1; i < iterations; i++)
                {
                    result = alg.ComputeHash(result);
                }
                return result;
            }
        }

        public string ComputeHash(string data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            return ComputeHash(data.ToByteArray()).ToBase64String();
        }

        public string ComputeHash(string data, int iterations)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            return ComputeHash(data.ToByteArray(), iterations).ToBase64String();
        }
    }
}
