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
            // A real implementation would validate the username and password
            // in the database and retrieve the matching ID. (The password should
            // use an iterative salted hash like BCRYPT.) For this simulation
            // that focuses on performance after the un/pw validation we just
            // pick the next availale ID.
            var id = Interlocked.Increment(ref m_nextId);

            // Get a truly random number for the key and make sure it's unique
            long key;
            do
            {
                var bytes = new byte[8];
                s_randomNumberGenerator.GetBytes(bytes);
                key = BitConverter.ToInt64(bytes, 0);
            } while (m_sessions.ContainsKey(key));

            // Create an authentication record. Even though we only use
            // 24 bytes, it is a full 1K in size to simulate storing other
            // things in the session record.
            var record = new AuthtRecord()
            {
                Key = key,
                Id = id,
                Expiration = DateTime.UtcNow + c_sessionExpiration
            };

            // Store the session in the hash table
            m_sessions[key] = record;

            // Return the key
            return key.ToString();
        }

        public string? ValidateToken(string token)
        {
            // Parse the key, defensively since tokens from browsers are untrusted data
            long key;
            if (!long.TryParse(token, out key)) return null;

            // See if there is a session record corresponding to this key
            AuthtRecord? rec;
            if (!m_sessions.TryGetValue(key, out rec)) return null;

            // Check whether the session has expired.
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

            // Simulated additional data that would be stored in a $SESSION_ collection (PHP) or
            // the equivalent.
            byte[] buffer = new byte[1000];
        }

    }
}
