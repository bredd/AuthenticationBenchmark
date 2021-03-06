using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace AuthtBenchmark
{
    internal static class Benchmark
    {
        const int c_views = 4;

        // Testing with multiple threads failed on AuthtDbSession and AuthtCrypto session.
        // For AuthtDbSession the Stream.Synchronized function isn't synchronizing correctly. So
        // another method to synchronize database access is needed. The problem is the separate
        // Seek and Read/Write calls. If a thread switch happens between seek and read then there's
        // an error. 
        // For AuthtCryptoSession the HMACSHA256 class doesn't seem to be thread save so each
        // operation needs to create its own copy.
        const int c_threads = 1;

        static Random s_random = new Random(Environment.TickCount);
        static int s_nextUser = 0;

        public static void TestAuthentication(IAuthtService authtService, int sessions)
        {
            Console.WriteLine($"Beginning Test: {authtService.GetType().Name}");

            var stopwatch = new Stopwatch();
            stopwatch.Start();

            var tasks = new Task[c_threads];
            for (int i = 0; i < c_threads; i++)
            {
                tasks[i] = Task.Run(() => TestThread(authtService, sessions/c_threads));
            }

            // Wait for all to finish
            Task.WaitAll(tasks);

            stopwatch.Stop();

            Console.WriteLine($"{stopwatch.Elapsed} for {sessions} sessions.");
            Console.WriteLine($"{((double)GC.GetTotalMemory(true)) / 1000000.0:F2}MB memory required.");
            Console.WriteLine();
        }

        static void TestThread(IAuthtService authtService, int sessions)
        {
            for (int userIndex = 0; userIndex < sessions; userIndex++)
            {
                string username = $"user{Interlocked.Increment(ref s_nextUser)}";
                string password = $"pw{s_random.Next()}";

                var token = authtService.Authenticate(username, password);
                if (token == null)
                {
                    Console.WriteLine("Failed authentication!");
                    throw new InvalidOperationException("Failed authentication.");
                }


                for (int i = 0; i < c_views; i++)
                {
                    if (authtService.ValidateToken(token) == null)
                    {
                        Console.WriteLine("Failed authorization!");
                        throw new InvalidOperationException("Failed authorization.");
                    }
                }
            }
        }

    }
}
