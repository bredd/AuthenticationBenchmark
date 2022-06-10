using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace AuthtBenchmark
{
    internal class AuthtMemSession : IAuthtService
    {
        static readonly TimeSpan c_sessionExpiration = TimeSpan.FromMinutes(30);

        static RandomNumberGenerator s_randomNumberGenerator = RandomNumberGenerator.Create();
        int m_nextId = 0;
        ConcurrentDictionary<long, AuthtRecord> m_sessions = new ConcurrentDictionary<long, AuthtRecord>();

        public string? Authenticate(string username, string password)
        {
            var id = Interlocked.Increment(ref m_nextId);

            // Get a truly random number and make sure it's unique
            long key;
            do
            {
                var bytes = new byte[8];
                s_randomNumberGenerator.GetBytes(bytes);
                key = BitConverter.ToInt64(bytes, 0);
            } while (m_sessions.ContainsKey(key));

            var record = new AuthtRecord()
            {
                Key = key,
                Id = id,
                Expiration = DateTime.UtcNow + c_sessionExpiration
            };

            m_sessions[key] = record;

            return key.ToString();
        }

        public string? ValidateToken(string token)
        {
            long key;
            if (!long.TryParse(token, out key)) return null;

            AuthtRecord? rec;
            if (!m_sessions.TryGetValue(key, out rec)) return null;

            if (rec.Expiration < DateTime.UtcNow) return null;

            return rec.Id.ToString();
        }

        class AuthtRecord
        {
            /// <summary>
            /// A random long integer that serves as the authentication token
            /// </summary>
            public long Key { get; set; }

            /// <summary>
            /// The user ID
            /// </summary>
            public int Id { get; set; }

            /// <summary>
            /// Expiration of this authentication record
            /// </summary>
            public DateTime Expiration { get; set; }

            byte[] buffer = new byte[1000];
        }

    }
}
