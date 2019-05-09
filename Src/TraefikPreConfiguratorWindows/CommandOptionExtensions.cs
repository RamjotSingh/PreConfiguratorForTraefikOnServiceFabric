// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace TraefikPreConfiguratorWindows
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
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
        /// Gets the values for the command option based if the value is to be fetched from commandline or Environment varibles.
        /// </summary>
        /// <param name="commandOption">The command option.</param>
        /// <param name="useEnvironmentVariable">True, if environment variable is to be used instead of command line.</param>
        /// <returns>Value for the command option.</returns>
        public static List<string> GetValuesExtended(this CommandOption commandOption, bool useEnvironmentVariable)
        {
            if (!commandOption.HasValueExtended(useEnvironmentVariable))
            {
                return null;
            }

            if (useEnvironmentVariable)
            {
                return Environment.GetEnvironmentVariable(commandOption.LongName).Split(',').ToList();
            }
            else
            {
                return commandOption.Values;
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

        /// <summary>
        /// Checks if a switch was specified by the user.
        /// </summary>
        /// <param name="commandOption">Command option.</param>
        /// <param name="useEnvironmentVariable">True if environment variable should be checked.</param>
        /// <returns>True if the switch was specified.</returns>
        public static bool IsSwitchSpecified(this CommandOption commandOption, bool useEnvironmentVariable)
        {
            if (useEnvironmentVariable)
            {
                if (commandOption.HasValueExtended(useEnvironmentVariable: true))
                {
                    string value = commandOption.GetValueExtended(useEnvironmentVariable: true);

                    return value.Equals("true", StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return commandOption.HasValue();
            }
        }
    }
}
