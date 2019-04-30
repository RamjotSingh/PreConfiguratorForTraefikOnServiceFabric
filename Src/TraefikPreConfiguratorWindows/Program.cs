// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace TraefikPreConfiguratorWindows
{
    using System;
    using Microsoft.Extensions.CommandLineUtils;

    /// <summary>
    /// Main program execution class.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Defines the entry point of the application.
        /// </summary>
        /// <param name="args">The arguments.</param>
        /// <remarks>
        /// Possible Arguments
        /// 1) If you want to dump the certs from local machine only and make it work for one environment config.
        ///     --ConfigureCerts "Certs" --ApplicationInsightsKey "AIKeyHere" --CertsToConfigure "ClusterCert;MyLocalMachine;ClusterCertThumbprint,SSLCert;MyLocalMachine;SSLCertThumbprint"
        /// 2) If you want to dump the certs from local machine and KeyVault and make it work for one environment config.
        ///     --ConfigureCerts "Certs" --ApplicationInsightsKey "AIKeyHere" --CertsToConfigure "ClusterCert;MyLocalMachine;ClusterCertThumbprint,SSLCert;KeyVault;SSLSecretName" --KeyVaultUri "https://dummyvault.vault.azure.net/" --KeyVaultClientId "1dc8b8b3-be3e-482a-b56b-9092c91aa4b2" -KeyVaultClientSecret "keyvaultappsecret"
        /// 3) If you want to dump the certs from local machine and make it work for different environments having different configs.
        ///     a) Set the arguments to --UseEnvironmentVariables (or -UseEnv)
        ///     b) And set the Environment variables
        ///         i) ConfigureCerts to Certs
        ///         ii) ApplicationInsightsKey to AiKeyHere
        ///         iii) CertsToConfigure to ClusterCert;MyLocalMachine;ClusterCertThumbprint,SSLCert;MyLocalMachine;SSLCertThumbprint
        ///        Similarily other options can be set in environment variables to enable rest of the options like KeyVault.
        /// </remarks>
        private static void Main(string[] args)
        {
            CommandLineApplication commandLineApplication = new CommandLineApplication(false);
            CommandOption useEnvironmentVariablesOption = commandLineApplication.Option(
                "-UseEnv | --UseEnvironmentVariables",
#pragma warning disable SA1118 // Parameter should not span multiple lines
                "Instead of using specified options, use Environment varibles with the same name (except the -- at start). This is to enable different integrations for different environments." +
                " If you use this, command line values are ignored.",
#pragma warning restore SA1118 // Parameter should not span multiple lines
                CommandOptionType.NoValue);
            CommandOption configureCertsOption = commandLineApplication.Option(
                "--ConfigureCerts <DirectoryRelativePath>",
                "Configures certs for Traefik by dropping them into the specifiec directory (relative to executing assembly). Certs are dropped in .key and .crt format.",
                CommandOptionType.SingleValue);
            CommandOption certsToConfigureOption = commandLineApplication.Option(
                "--CertsToConfigure <FormattedCertsToConfigure>",
#pragma warning disable SA1118 // Parameter should not span multiple lines
                "The value looks something like SSLCert;MyLocalMachine;7ce597cba5ae055fa37f222aaffc1007c3d61277,ClusterCert;KeyVault;ClusterCertSecretName. The format is" +
                "NameOfTheCert1;Source1;<Cert identifier1>,NameOfCert2;Source2;<Cert identifier2>." +
                "Possible Source values are 'MyLocalMachine' which fetches certs from Personal under LocalMachine Store and " +
                "'KeyVault' which fetches the cert from KeyVault. If KeyVault is specified, Specify ClientId and secret using --KeyVaultUri, --KeyVaultClientId, --KeyVaultClientSecret or --KeyVaultClientCert",
#pragma warning restore SA1118 // Parameter should not span multiple lines
                CommandOptionType.SingleValue);
            CommandOption keyVaultUriOption = commandLineApplication.Option(
                "--KeyVaultUri <KeyVaultUri>",
                "Uri to use for KeyVault connection. Use --KeyVaultClientId to specify ClientId of the app to use to access Key Vault.",
                CommandOptionType.SingleValue);
            CommandOption keyVaultClientIdOption = commandLineApplication.Option(
                "--KeyVaultClientId <ClientId>",
                "Client Id to use for KeyVault connection. Specify the secret by using --KeyVaultClientSecret or --KeyVaultClientCert.",
                CommandOptionType.SingleValue);
            CommandOption keyVaultClientSecretOption = commandLineApplication.Option(
                "--KeyVaultClientSecret <ClientSecret>",
                "Client secret to use for KeyVault connection. Specify the ClientId using --KeyVaultClientId.",
                CommandOptionType.SingleValue);
            CommandOption useManagedIdentity = commandLineApplication.Option(
                "--UseManagedIdentity",
                "Uses Managed Identity for authenticating with KeyVault. You can specify the client Id if you want to use one in --KeyVaultClientId option.",
                CommandOptionType.NoValue);
            CommandOption keyVaultClientCertThumbprintOption = commandLineApplication.Option(
                "--KeyVaultClientCert <ClientCertThumbprint>",
                "Cert thumbprint to be used to contact key vault. The cert needs to be present on the machine. Specify the ClientId using --KeyVaultClientId.",
                CommandOptionType.SingleValue);
            CommandOption applicationInsightsInstrumentationKeyOption = commandLineApplication.Option(
                "--ApplicationInsightsKey <InstrumentationKey>",
                "Instrumentation key to push traces for PreConfiguration into Application Insights.",
                CommandOptionType.SingleValue);
            commandLineApplication.HelpOption("-h|--help|-?");
            commandLineApplication.OnExecute(async () =>
            {
                try
                {
                    bool useEnvironmentVariables = useEnvironmentVariablesOption.HasValue();
                    if (applicationInsightsInstrumentationKeyOption.HasValueExtended(useEnvironmentVariables))
                    {
                        Logger.ConfigureLogger(applicationInsightsInstrumentationKeyOption.GetValueExtended(useEnvironmentVariables));
                    }

                    if (configureCertsOption.HasValueExtended(useEnvironmentVariables))
                    {
                        ExitCode certHandlerExitCode = await CertificateHandler.ProcessAsync(
                            configureCertsOption.GetValueExtended(useEnvironmentVariables),
                            certsToConfigureOption.GetValueExtended(useEnvironmentVariables),
                            keyVaultUriOption.GetValueExtended(useEnvironmentVariables),
                            keyVaultClientIdOption.GetValueExtended(useEnvironmentVariables),
                            keyVaultClientSecretOption.GetValueExtended(useEnvironmentVariables),
                            keyVaultClientCertThumbprintOption.GetValueExtended(useEnvironmentVariables),
                            !string.IsNullOrEmpty(useManagedIdentity.GetValueExtended(useEnvironmentVariables))).ConfigureAwait(false);

                        if (certHandlerExitCode != ExitCode.Success)
                        {
                            return (int)certHandlerExitCode;
                        }
                    }

                    return (int)ExitCode.Success;
                }
                catch (AggregateException aggrEx)
                {
                    foreach (Exception innerException in aggrEx.InnerExceptions)
                    {
                        Logger.LogError(CallInfo.Site(), innerException);
                    }

                    return (int)ExitCode.UnknownFailure;
                }
                catch (Exception ex)
                {
                    Logger.LogError(CallInfo.Site(), ex);

                    return (int)ExitCode.UnknownFailure;
                }
            });

            commandLineApplication.Execute(args);
            Logger.Flush();
        }
    }
}
