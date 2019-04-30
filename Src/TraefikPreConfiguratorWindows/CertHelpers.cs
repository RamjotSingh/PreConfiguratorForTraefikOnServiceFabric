// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace TraefikPreConfiguratorWindows
{
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Certificate helpers.
    /// </summary>
    internal static class CertHelpers
    {
        /// <summary>
        /// Finds the certificates with given parameters.
        /// </summary>
        /// <param name="certificateFindValue">The certificate find value. This is the value we search on.</param>
        /// <param name="x509FindType">Type of the X509 find.</param>
        /// <param name="storeName">Name of the store.</param>
        /// <param name="storeLocation">The store location.</param>
        /// <returns>Collection of certificates.</returns>
        public static X509Certificate2Collection FindCertificates(
            object certificateFindValue,
            X509FindType x509FindType = X509FindType.FindByThumbprint,
            StoreName storeName = StoreName.My,
            StoreLocation storeLocation = StoreLocation.LocalMachine)
        {
            X509Store certificateStore = new X509Store(storeName, storeLocation);

            certificateStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = certificateStore.Certificates.Find(x509FindType, certificateFindValue, false);
            certificateStore.Close();

            return certCollection;
        }
    }
}
