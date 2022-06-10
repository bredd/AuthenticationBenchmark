using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace AuthtBenchmark
{
    internal class AuthtDbSession : IAuthtService
    {
        const int c_minRecordSize = 24; // Three longs
        const int c_recordSize = 1024; // Buffered for realistic session info
        static readonly TimeSpan c_sessionExpiration = TimeSpan.FromMinutes(30);

        string m_databaseFilename;
        Stream m_database;
        static RandomNumberGenerator s_randomNumberGenerator = RandomNumberGenerator.Create();
        int m_nextId = 0;

        public AuthtDbSession()
        {
            m_databaseFilename = Path.GetTempFileName();
            m_database = new FileStream(m_databaseFilename, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }

        ~AuthtDbSession()
        {
            // If this were a real operation, there would be a disposer but
            // for this benchmark we can use a finalizer.
            m_database.Dispose();
            File.Delete(m_databaseFilename);
            Console.WriteLine($"Deleted database: {m_databaseFilename}");
        }

        public string Authenticate(string username, string password)
        {
            var id = (long)Interlocked.Increment(ref m_nextId);

            // Get a truly random number
            long key;
            {
                var bytes = new byte[8];
                s_randomNumberGenerator.GetBytes(bytes);
                key = BitConverter.ToInt64(bytes, 0);
            }

            var expiration = DateTime.UtcNow + c_sessionExpiration;

            // Three longs = 24 bytes per record
            var record = new byte[c_recordSize];
            using (var writer = record.GetWriter())
            {
                writer.Write(key);
                writer.Write(id);
                writer.Write(expiration.ToBinary());
            }

            // Write the record
            {
                var synchronized = Stream.Synchronized(m_database);
                synchronized.Position = id * c_recordSize;
                synchronized.Write(record, 0, c_recordSize);
                synchronized.Flush();
            }

            return $"{id}*{key}";
        }

        public string? ValidateToken(string token)
        {
            var pair = token.Split('*');
            if (pair.Length != 2) return null;

            if (!long.TryParse(pair[0], out long id)) return null;
            if (!long.TryParse(pair[1], out long key)) return null;

            if ((id + 1) * c_recordSize > m_database.Length) return null;

            var record = new byte[c_recordSize];
            {
                var synchronized = Stream.Synchronized(m_database);
                synchronized.Position = id * c_recordSize;
                synchronized.Read(record, 0, c_recordSize);
            }

            // Read the record
            long recKey;
            long recId;
            DateTime expiration;
            using (var reader = record.GetReader())
            {
                recKey = reader.ReadInt64();
                recId = reader.ReadInt64();
                expiration = DateTime.FromBinary(reader.ReadInt64());
            }

            if (recKey != key) return null;
            if (recId != id) return null;
            if (expiration < DateTime.UtcNow) return null;

            return recId.ToString();
        }
    }
}
