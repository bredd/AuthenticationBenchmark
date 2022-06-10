using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthtBenchmark
{
    internal interface IAuthtService
    {
        /// <summary>
        /// Authenticates a user.
        /// </summary>
        /// <param name="username">The username</param>
        /// <param name="password">The password</param>
        /// <returns>A token that can later be tested using ValidateToken</returns>
        string? Authenticate(string username, string password);

        /// <summary>
        /// Validates an authentication token
        /// </summary>
        /// <param name="token">Token to validate</param>
        /// <returns>The userId corresponding to this token.</returns>
        string? ValidateToken(string token);
    }
}
