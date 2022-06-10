using AuthtBenchmark;

const int c_testSessions = 2000000;

Benchmark.TestAuthentication(new AuthtMemSession(), c_testSessions);
//Benchmark.TestAuthentication(new AuthtDbSession(), c_testSessions);
//Benchmark.TestAuthentication(new AuthtCryptoSession(), c_testSessions);



