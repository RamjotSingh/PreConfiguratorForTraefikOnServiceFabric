// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace TraefikPreConfiguratorWindows
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Azure.KeyVault;
    using Microsoft.Azure.KeyVault.Models;
    using Microsoft.Azure.Services.AppAuthentication;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.Rest.Azure;

    /// <summary>
    /// Performs Certificate related tasks.
    /// </summary>
    internal static class CertificateHandler
    {
        /// <summary>
        /// Arguments to be used to extract .key out of .Pfx.
        /// </summary>
        private const string PrivateKeyExportArguments = "pkcs12 -in \"\"{0}\"\" -nocerts -nodes -out \"\"{1}\"\" -passin pass:{2}";

        /// <summary>
        /// Arguments to be used to extract .crt out of .Pfx.
        /// </summary>
        private const string PublicKeyExportArguments = "pkcs12 -in \"\"{0}\"\" -clcerts -nokeys -out \"\"{1}\"\" -passin pass:{2}";

        /// <summary>
        /// Processes the certificate management.
        /// </summary>
        /// <param name="directoryPath">Directory to put the certificatex in.</param>
        /// <param name="certConfiguration">Certificate configuration. This is a combination of comma separated values in following format
        /// *certFileName*;*SourceOfCert*;*CertIdentifierInSource*.</param>
        /// <param name="keyVaultUris">KeyVault uris if key vault is to be used.</param>
        /// <param name="keyVaultClientId">Application client Id to access keyvault.</param>
        /// <param name="keyVaultClientSecret">Application client secret to access keyvault.</param>
        /// <param name="keyVaultClientCert">Application client certificate thumbprint if the keyvault app has certificate credentials.</param>
        /// <param name="useManagedIdentity">Use managed identity.</param>
        /// <returns>Exit code for the operation.</returns>
        internal static async Task<ExitCode> ProcessAsync(
            string directoryPath,
            string certConfiguration,
            List<string> keyVaultUris,
            string keyVaultClientId,
            string keyVaultClientSecret,
            string keyVaultClientCert,
            bool useManagedIdentity)
        {
            if (string.IsNullOrEmpty(directoryPath))
            {
                Logger.LogError(CallInfo.Site(), "Directory path missing for the Certificate directory.");
                return ExitCode.DirectoryPathMissing;
            }

            if (string.IsNullOrEmpty(certConfiguration))
            {
                Logger.LogError(CallInfo.Site(), "Cert configuration missing. Please specify CertsToConfigure option");
                return ExitCode.InvalidCertConfiguration;
            }

            // 1. Initialize KeyVault Client if params were passed.
            KeyVaultClient keyVaultClient = null;
            Dictionary<string, string> keyVaultSecretMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (keyVaultUris.Any())
            {
                KeyVaultClient.AuthenticationCallback callback = null;

                if (useManagedIdentity)
                {
                    string connectionString = "RunAs=App";

                    if (!string.IsNullOrEmpty(keyVaultClientId))
                    {
                        connectionString = connectionString + ";AppId=" + keyVaultClientId;
                    }

                    AzureServiceTokenProvider tokenProvider = new AzureServiceTokenProvider(connectionString);
                    callback = new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback);
                }
                else
                {
                    if (string.IsNullOrEmpty(keyVaultClientId))
                    {
                        Logger.LogError(CallInfo.Site(), "If KeyVaultUri is specified and managed identity is not used, KeyVault ClientId must be specified");
                        return ExitCode.KeyVaultConfigurationIncomplete;
                    }

                    if (string.IsNullOrEmpty(keyVaultClientSecret) && string.IsNullOrEmpty(keyVaultClientCert))
                    {
                        Logger.LogError(CallInfo.Site(), "If KeyVaultUri is specified and managed identity is not used, KeyVault ClientSecret or KeyVault ClientCert must be specified");
                        return ExitCode.KeyVaultConfigurationIncomplete;
                    }

                    if (!string.IsNullOrEmpty(keyVaultClientSecret))
                    {
                        callback =
                            (authority, resource, scope) => GetTokenFromClientSecretAsync(authority, resource, keyVaultClientId, keyVaultClientSecret);
                    }
                    else
                    {
                        X509Certificate2Collection keyVaultCerts = CertHelpers.FindCertificates(keyVaultClientCert, X509FindType.FindByThumbprint);

                        if (keyVaultCerts.Count == 0)
                        {
                            Logger.LogError(CallInfo.Site(), "Failed to find Client cert with thumbprint '{0}'", keyVaultClientCert);
                            return ExitCode.KeyVaultConfigurationIncomplete;
                        }

                        callback =
                            (authority, resource, scope) => GetTokenFromClientCertificateAsync(authority, resource, keyVaultClientId, keyVaultCerts[0]);
                    }
                }

                keyVaultClient = new KeyVaultClient(callback);

                foreach (string keyVaultUri in keyVaultUris)
                {
                    IPage<SecretItem> secrets = await keyVaultClient.GetSecretsAsync(keyVaultUri).ConfigureAwait(false);

                    foreach (SecretItem secret in secrets)
                    {
                        keyVaultSecretMap[secret.Identifier.Name] = keyVaultUri;
                    }

                    while (!string.IsNullOrEmpty(secrets.NextPageLink))
                    {
                        secrets = await keyVaultClient.GetSecretsNextAsync(secrets.NextPageLink).ConfigureAwait(false);

                        foreach (SecretItem secret in secrets)
                        {
                            keyVaultSecretMap[secret.Identifier.Name] = keyVaultUri;
                        }
                    }
                }
            }

            // 2. Figure all the certs which need processing.
            string[] certsToConfigure = certConfiguration.Split(',');
            string currentExeDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string fullDirectoryPathForCerts = Path.Combine(currentExeDirectory, directoryPath);

            // 3. Process specified certs one by one.
            foreach (string certToConfigure in certsToConfigure)
            {
                // 3a. Split the cert configuration data to get actual details. This data is informat
                // <CertNameOnDisk>;CertSource(LocalMachine or KeyVault);<CertIdentifier(SecretName or Thumbprint)>
                string[] certConfigurationParams = certToConfigure.Split(';');

                if (certConfigurationParams.Length != 3)
                {
                    Logger.LogError(CallInfo.Site(), "Invalid certificate configuration '{0}'. Cert configuration must be in format <CertFileName>;<CertSource>;<CertIdentifier>", certToConfigure);
                    return ExitCode.InvalidCertConfiguration;
                }

                var certConfig =
                    new { CertName = certConfigurationParams[0], CertSource = certConfigurationParams[1], CertIdentifier = certConfigurationParams[2] };

                // 3b. Depending on the source of Cert get the PFX for the certs dropped into the directory.
                if (certConfig.CertSource.Equals("MyLocalMachine", StringComparison.OrdinalIgnoreCase))
                {
                    ExitCode localMachineCertHandler = await LocalMachineCertHandlerAsync(
                        certConfig.CertName,
                        certConfig.CertIdentifier,
                        fullDirectoryPathForCerts).ConfigureAwait(false);

                    if (localMachineCertHandler != ExitCode.Success)
                    {
                        return localMachineCertHandler;
                    }
                }
                else if (certConfig.CertSource.Equals("KeyVault", StringComparison.OrdinalIgnoreCase))
                {
                    if (!keyVaultSecretMap.TryGetValue(certConfig.CertIdentifier, out string keyVaultUri))
                    {
                        Logger.LogError(CallInfo.Site(), "Certificate with name '{0}' missing from all specified KeyVaults", certConfig.CertIdentifier);
                        return ExitCode.CertificateMissingFromSource;
                    }

                    ExitCode keyVaultCertHandlerExitCode = await KeyVaultCertHandlerAsync(
                        certConfig.CertName,
                        certConfig.CertIdentifier,
                        fullDirectoryPathForCerts,
                        keyVaultClient,
                        keyVaultUri).ConfigureAwait(false);

                    if (keyVaultCertHandlerExitCode != ExitCode.Success)
                    {
                        return keyVaultCertHandlerExitCode;
                    }
                }
                else
                {
                    Logger.LogError(CallInfo.Site(), "Unsupported Certificate source '{0}' for cert '{1}'", certConfig.CertSource, certConfig.CertName);
                    return ExitCode.UnsupportedCertSource;
                }

                // 3c. Convert PFX into .Key and .Crt. We are placing openssl next to this exe hence using current directory.
                ExitCode conversionExitCode = ConvertPfxIntoPemFormat(certConfig.CertName, fullDirectoryPathForCerts, currentExeDirectory, password: string.Empty);

                if (conversionExitCode != ExitCode.Success)
                {
                    return conversionExitCode;
                }

                // 3d. Delete the PFX as it is no longer needed.
                File.Delete(Path.Combine(fullDirectoryPathForCerts, certConfig.CertName + ".pfx"));
            }

            return ExitCode.Success;
        }

        /// <summary>
        /// Gets the token from client secret. This method is used as AuthCallback for KeyVault client.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="resource">The resource.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <returns>Access token.</returns>
        private static async Task<string> GetTokenFromClientSecretAsync(string authority, string resource, string clientId, string clientSecret)
        {
            var authContext = new AuthenticationContext(authority);
            var clientCred = new ClientCredential(clientId, clientSecret);
            var result = await authContext.AcquireTokenAsync(resource, clientCred).ConfigureAwait(false);
            return result.AccessToken;
        }

        /// <summary>
        /// Gets the token from client certificate. This method is used as AuthCallback for KeyVault client.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="resource">The resource.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="certificate">The certificate.</param>
        /// <returns>Access token.</returns>
        private static async Task<string> GetTokenFromClientCertificateAsync(string authority, string resource, string clientId, X509Certificate2 certificate)
        {
            var authContext = new AuthenticationContext(authority);
            var result = await authContext.AcquireTokenAsync(resource, new ClientAssertionCertificate(clientId, certificate)).ConfigureAwait(false);
            return result.AccessToken;
        }

        /// <summary>
        /// Extracts PFX from a local cert present in LocalMachine store under My.
        /// </summary>
        /// <param name="certificateName">Name of the certificate.</param>
        /// <param name="certificateIdentitier">The certificate identifier.</param>
        /// <param name="fullDirectoryPath">The full directory path to drop PFX at.</param>
        /// <returns>Exit code for the operation.</returns>
        private static Task<ExitCode> LocalMachineCertHandlerAsync(string certificateName, string certificateIdentitier, string fullDirectoryPath)
        {
            // Split the Certificate identifier on :. If we don't find ':' then we assume the identifier is a thumbprint,
            // otherwise we try to figure what identifier the user gave. We support X509FindType values as string.
            string[] certIdentifierSplit = certificateIdentitier.Split(':');

            X509FindType x509FindType = X509FindType.FindByThumbprint;

            if (certIdentifierSplit.Length > 1)
            {
                if (!Enum.TryParse<X509FindType>(certIdentifierSplit[1], out x509FindType))
                {
                    Logger.LogError(CallInfo.Site(), "Invalid Find type value used '{0}' in Ceritificate identifier '{1}'", certIdentifierSplit[1], certificateIdentitier);
                    return Task.FromResult(ExitCode.InvalidCertConfiguration);
                }
            }

            X509Certificate2Collection certificateCollection = CertHelpers.FindCertificates(
                certIdentifierSplit[0],
                x509FindType,
                StoreName.My,
                StoreLocation.LocalMachine);

            if (certificateCollection.Count == 0)
            {
                Logger.LogError(CallInfo.Site(), "Failed to find certificate with name '{0}'", certificateName);
                return Task.FromResult(ExitCode.CertificateMissingFromSource);
            }

            X509Certificate2 selectedCertificate = certificateCollection[0];

            // If more than 1 cert is found, choose the one with latest expiry.
            if (certificateCollection.Count > 1)
            {
                Logger.LogInfo(CallInfo.Site(), "Found multiple certificates which match the search identifier, selecting the one with latest expiry");

                foreach (X509Certificate2 x509Certificate2 in certificateCollection)
                {
                    // If the first selected certificate did not have a private key on it and
                    // we found another cert with private key pick that up.
                    if (!selectedCertificate.HasPrivateKey && x509Certificate2.HasPrivateKey)
                    {
                        selectedCertificate = x509Certificate2;
                    }

                    if (x509Certificate2.NotAfter > selectedCertificate.NotAfter && x509Certificate2.HasPrivateKey)
                    {
                        selectedCertificate = x509Certificate2;
                    }
                }
            }

            if (!selectedCertificate.HasPrivateKey)
            {
                Logger.LogError(CallInfo.Site(), "Certificate with name '{0}' and thumbprint '{1}' has missing Private Key", certificateName, selectedCertificate.Thumbprint);
                return Task.FromResult(ExitCode.PrivateKeyMissingOnCertificate);
            }

            byte[] rawCertData = selectedCertificate.Export(X509ContentType.Pfx);

            return Task.FromResult(SaveCertificatePrivateKeyToDisk(rawCertData, certificateName, fullDirectoryPath));
        }

        /// <summary>
        /// Extracts PFX from a certificate uploaded or generated from KeyVault. This does not support certs uploaded into KeyVault using secret.
        /// </summary>
        /// <param name="certificateName">Name of the certificate.</param>
        /// <param name="certificateSecretName">Secret name of the certificate. This is usually certificate name.</param>
        /// <param name="fullDirectoryPath">The full directory path to drop PFX at.</param>
        /// <param name="keyVaultClient">The key vault client.</param>
        /// <param name="keyVaultUrl">The key vault URL.</param>
        /// <returns>Exit code for the operation.</returns>
        private static async Task<ExitCode> KeyVaultCertHandlerAsync(
            string certificateName,
            string certificateSecretName,
            string fullDirectoryPath,
            KeyVaultClient keyVaultClient,
            string keyVaultUrl)
        {
            if (keyVaultClient == null)
            {
                Logger.LogError(CallInfo.Site(), "KeyVaultClient was not initialized. Make sure required params for KeyVault connection were passed");
                return ExitCode.KeyVaultConfigurationIncomplete;
            }

            if (string.IsNullOrEmpty(keyVaultUrl))
            {
                Logger.LogError(CallInfo.Site(), "Invalid KeyVault uri.");
                return ExitCode.KeyVaultConfigurationIncomplete;
            }

            SecretBundle certificateSecret;
            try
            {
                certificateSecret = await keyVaultClient.GetSecretAsync(keyVaultUrl, certificateSecretName).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.LogError(CallInfo.Site(), ex, "Failed to get certificate with secret name '{0}' from key vault '{1}'", certificateSecretName, keyVaultUrl);
                return ExitCode.KeyVaultOperationFailed;
            }

            // Only supporting managed certs for now.
            if (certificateSecret.Managed != true)
            {
                Logger.LogError(CallInfo.Site(), "Failed to decrypt certificate. Only managed certificates are supported. Download the unmanaged cert from secret and reupload it to certificates.");
                return ExitCode.FailedToDecodeCertFromKeyVault;
            }

            return SaveCertificatePrivateKeyToDisk(Convert.FromBase64String(certificateSecret.Value), certificateName, fullDirectoryPath);
        }

        /// <summary>
        /// Saves the certificate private key in PFX format to disk.
        /// </summary>
        /// <param name="rawCertData">Raw certificate bytes.</param>
        /// <param name="certificateName">Name of the certificate (This is the name of the pfx file).</param>
        /// <param name="fullDirectoryPath">The full directory path.</param>
        /// <returns>Exit code for the operation.</returns>
        private static ExitCode SaveCertificatePrivateKeyToDisk(byte[] rawCertData, string certificateName, string fullDirectoryPath)
        {
            Directory.CreateDirectory(fullDirectoryPath);

            File.WriteAllBytes(Path.Combine(fullDirectoryPath, certificateName + ".pfx"), rawCertData);
            return ExitCode.Success;
        }

        /// <summary>
        /// Converts the PFX into pem format and extracts the Private key into .key and public in .crt format.
        /// </summary>
        /// <param name="certificateName">Name of the certificate.</param>
        /// <param name="certDirectoryPath">The full directory path for the PFX file. This is also the same path where the PEM and CRT files will be placed.</param>
        /// <param name="opensslExeDirectory">The openssl executable directory.</param>
        /// <param name="password">PFX password.</param>
        /// <returns>Exit code for the operation.</returns>
        private static ExitCode ConvertPfxIntoPemFormat(string certificateName, string certDirectoryPath, string opensslExeDirectory, string password)
        {
            string opensslPath = Path.Combine(opensslExeDirectory, "openssl.exe");
            string pathToPfx = Path.Combine(certDirectoryPath, certificateName + ".pfx");

            string keyExtractionProcessArgs = string.Format(
                CultureInfo.InvariantCulture,
                PrivateKeyExportArguments,
                pathToPfx,
                Path.Combine(certDirectoryPath, certificateName + ".key"),
                password);

            Logger.LogVerbose(CallInfo.Site(), "Starting extraction of Private key for '{0}' using '{0}'", certificateName, opensslPath);
            int exportPrivateKeyExitCode = ExecuteOpensslProcess(opensslPath, keyExtractionProcessArgs);
            Logger.LogVerbose(CallInfo.Site(), "Private key extraction for certificate '{0}' process completed with exit code '{1}'", certificateName, exportPrivateKeyExitCode);

            if (exportPrivateKeyExitCode != 0)
            {
                Logger.LogError(CallInfo.Site(), "Private key extraction failed for certificate name '{0}'", certificateName);
                return ExitCode.PrivateKeyExtractionFailed;
            }

            string crtExtractionProcessArgs = string.Format(
                CultureInfo.InvariantCulture,
                PublicKeyExportArguments,
                pathToPfx,
                Path.Combine(certDirectoryPath, certificateName + ".crt"),
                password);

            Logger.LogVerbose(CallInfo.Site(), "Starting extraction of Public key from PFX using '{0}'", opensslPath);
            int exportPublicKeyExitCode = ExecuteOpensslProcess(opensslPath, crtExtractionProcessArgs);
            Logger.LogVerbose(CallInfo.Site(), "Public key extraction for certificate '{0}' process completed with exit code '{1}'", certificateName, exportPublicKeyExitCode);

            if (exportPublicKeyExitCode != 0)
            {
                Logger.LogError(CallInfo.Site(), "Public key extraction failed for certificate name '{0}'", certificateName);
                return ExitCode.PublicKeyExtractionFailed;
            }

            return ExitCode.Success;
        }

        private static int ExecuteOpensslProcess(string opensslPath, string arguments)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo(
                opensslPath,
                arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            Process process = Process.Start(processStartInfo);
            process.WaitForExit(milliseconds: 60 * 1000);

            // If the process hung and failed to exit, cancel it.
            if (!process.HasExited)
            {
                process.Kill();
                return -999;
            }

            return process.ExitCode;
        }
    }
}
