// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace TraefikPreConfiguratorWindows
{
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Certificate helpers.
    /// </summary>
    public static class CertHelpers
    {
        /// <summary>
        /// Finds the certificate by thumbprint.
        /// </summary>
        /// <param name="certThumbprint">The cert thumbprint.</param>
        /// <param name="storeName">Name of the store.</param>
        /// <param name="storeLocation">The store location.</param>
        /// <returns>Certificate object if found, null otherwise.</returns>
        public static X509Certificate2 FindCertificateByThumbprint(string certThumbprint, StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.LocalMachine)
        {
            using (X509Store x509Store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                x509Store.Open(OpenFlags.ReadOnly);
                try
                {
                    X509Certificate2Collection certificateCollection = x509Store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, validOnly: false);

                    if (certificateCollection.Count == 0)
                    {
                        return null;
                    }
                    else
                    {
                        return certificateCollection[0];
                    }
                }
                finally
                {
                    x509Store.Close();
                }
            }
        }
    }
}
