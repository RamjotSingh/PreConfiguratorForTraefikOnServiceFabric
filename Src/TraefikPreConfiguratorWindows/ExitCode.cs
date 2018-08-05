// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace TraefikPreConfiguratorWindows
{
    /// <summary>
    /// Exit codes.
    /// </summary>
    public enum ExitCode
    {
        /// <summary>
        /// Process completed successfully.
        /// </summary>
        Success = 0,

        /// <summary>
        /// Unknown failure occurred during execution.
        /// </summary>
        UnknownFailure = -1,

        /// <summary>
        /// Directory path is missing in the configuration.
        /// </summary>
        DirectoryPathMissing = -2,

        /// <summary>
        /// KeyVault configuration is incomplete.
        /// </summary>
        KeyVaultConfigurationIncomplete = -3,

        /// <summary>
        /// Invalid certificates configuration.
        /// </summary>
        InvalidCertConfiguration = -4,

        /// <summary>
        /// Certificate could not the be found in the given source (localmachine or KeyVault).
        /// </summary>
        CertificateMissingFromSource = -5,

        /// <summary>
        /// Private key missing for the ceritifcate to export.
        /// </summary>
        PrivateKeyMissingOnCertificate = -6,

        /// <summary>
        /// KeyVault operation failed.
        /// </summary>
        KeyVaultOperationFailed = -7,

        /// <summary>
        /// Failed to decode certificate from keyvault. This usually points to certificate uploaded using secrets and not certificate option on keyvault.
        /// </summary>
        FailedToDecodeCertFromKeyVault = -8,

        /// <summary>
        /// Private key extraction for the certificate.
        /// </summary>
        PrivateKeyExtractionFailed = -9,

        /// <summary>
        /// Public key extraction failed for the certificate.
        /// </summary>
        PublicKeyExtractionFailed = -10,

        /// <summary>
        /// Unsupported certificate source. Currently supported sources are LocalMachine and KeyVault.
        /// </summary>
        UnsupportedCertSource = -11,
    }
}
