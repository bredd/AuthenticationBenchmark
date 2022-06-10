using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace AuthtBenchmark
{
    internal class AuthtCryptoSession : IAuthtService
    {
        static readonly TimeSpan c_sessionExpiration = TimeSpan.FromMinutes(30);
        const int c_dataSize = 8 + 8; // Id (8 bytes) + Expiration (8 bytes);
        const int c_macSize = 32; // 256 bits
        const int c_recordSize = c_dataSize + c_macSize;

        HMACSHA256 s_hmac;
        int m_nextId = 0;

        public AuthtCryptoSession()
        {
            // Automatically gets a random key. In the real world we would have to store
            // and retrieve the key but for the benchmark this is good enough.
            s_hmac = new HMACSHA256();
        }

        public string Authenticate(string username, string password)
        {
            var id = (long)Interlocked.Increment(ref m_nextId);
            var expiration = DateTime.UtcNow + c_sessionExpiration;

            var record = new byte[c_recordSize];
            using (var writer = record.GetWriter())
            {
                writer.Write(id);
                writer.Write(expiration.ToBinary());
            }

            // Calculate the MAC
            var hash = s_hmac.ComputeHash(record, 0, 16);
            System.Diagnostics.Debug.Assert(hash.Length == c_macSize);

            // Add the MAC to the record
            Buffer.BlockCopy(hash, 0, record, c_dataSize, c_macSize);

            // Convert to string
            return Convert.ToBase64String(record);
        }

        public string? ValidateToken(string token)
        {
            // Decode the record
            var record = Convert.FromBase64String(token);
            if (record.Length != c_recordSize) return null;

            // Recalculate the MAC
            var hash = s_hmac.ComputeHash(record, 0, 16);

            // See if they match
            if (!BufferEquals(hash, 0, record, c_dataSize, c_macSize)) return null;

            var id = BitConverter.ToInt64(record, 0);
            var expiration = DateTime.FromBinary(BitConverter.ToInt64(record, 8));

            if (expiration < DateTime.UtcNow) return null;

            return id.ToString();
        }

        static bool BufferEquals(byte[] a, int offsetA, byte[] b, int offsetB, int length)
        {
            for (int i = 0; i < length; i++)
            {
                if (a[offsetA + i] != b[offsetB + i]) return false;
            }
            return true;
        }
    }
}
