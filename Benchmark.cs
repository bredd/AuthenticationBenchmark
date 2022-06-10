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
        const int c_users = 2000000;
        const int c_views = 4;

        const int c_threads = 1;
        const int c_usersPerThread = c_users / c_threads;

        static Random s_random = new Random(Environment.TickCount);
        static int s_nextUser = 0;

        public static void TestAuthentication(IAuthtService authtService)
        {
            Console.WriteLine($"Beginning Test: {authtService.GetType().Name}");

            var stopwatch = new Stopwatch();
            stopwatch.Start();

            var tasks = new Task[c_threads];
            for (int i = 0; i < c_threads; i++)
            {
                tasks[i] = Task.Run(() => TestThread(authtService));
            }

            // Wait for all to finish
            Task.WaitAll(tasks);

            stopwatch.Stop();

            Console.WriteLine($"{stopwatch.Elapsed} for {c_users} sessions.");
            Console.WriteLine($"{((double)GC.GetTotalMemory(true)) / 1000000.0:F2}MB memory required.");
            Console.WriteLine();
        }

        static void TestThread(IAuthtService authtService)
        {
            for (int userIndex = 0; userIndex < c_usersPerThread; userIndex++)
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
