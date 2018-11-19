// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace TraefikPreConfiguratorWindows
{
    using System;
    using Microsoft.Extensions.CommandLineUtils;

    /// <summary>
    /// Command option extnsions.
    /// </summary>
    public static class CommandOptionExtensions
    {
        /// <summary>
        /// Gets the value for the command option based if the value is to be fetched from commandline or Environment varibles.
        /// </summary>
        /// <param name="commandOption">The command option.</param>
        /// <param name="useEnvironmentVariable">True, if environment variable is to be used instead of command line.</param>
        /// <returns>Value for the command option.</returns>
        public static string GetValueExtended(this CommandOption commandOption, bool useEnvironmentVariable)
        {
            if (!commandOption.HasValueExtended(useEnvironmentVariable))
            {
                return null;
            }

            if (useEnvironmentVariable)
            {
                return Environment.GetEnvironmentVariable(commandOption.LongName);
            }
            else
            {
                return commandOption.Value();
            }
        }

        /// <summary>
        /// Determines whether the command option has value or not based on if the value needs to be pulled from command line of environment variables.
        /// </summary>
        /// <param name="commandOption">The command option.</param>
        /// <param name="useEnvironmentVariable">if set to <c>true</c> [use environment variable].</param>
        /// <returns>
        ///   <c>true</c> if command option has value; otherwise, <c>false</c>.
        /// </returns>
        public static bool HasValueExtended(this CommandOption commandOption, bool useEnvironmentVariable)
        {
            if (useEnvironmentVariable)
            {
                return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(commandOption.LongName));
            }
            else
            {
                return commandOption.HasValue();
            }
        }
    }
}
