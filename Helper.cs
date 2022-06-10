using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthtBenchmark
{
    internal static class Helper
    {
        static readonly UTF8Encoding s_Utf8NoBom = new UTF8Encoding(false);

        public static BinaryWriter GetWriter(this byte[] bytes)
        {
            return new BinaryWriter(new MemoryStream(bytes), s_Utf8NoBom, false);
        }

        public static BinaryReader GetReader(this byte[] bytes)
        {
            return new BinaryReader(new MemoryStream(bytes), s_Utf8NoBom, false);
        }
    }
}
