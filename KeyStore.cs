using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using IdentityServer4.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace IdentityServer4.KeyManagement.AzureKeyVault
{
    public abstract class KeyStore
    {
        private readonly CertificateClient _CertificateClient;
        private readonly SecretClient _SecretClient;

        public KeyStore(TokenCredential tokenCredential, string vault)
        {
            var vaultUri = new Uri(vault);
            this._CertificateClient = new CertificateClient(vaultUri, tokenCredential);
            this._SecretClient = new SecretClient(vaultUri, tokenCredential);
        }

        internal async Task<List<KeyVaultCertificate>> GetAllEnabledCertificateVersionsAsync(string certificateName)
        {
            var properties = new List<CertificateProperties>();
            // Get all the certificate versions (this will also get the currect active version)
            // Find all enabled versions of the certificate and sort them by creation date in decending order 
            await foreach (var certVersion in this._CertificateClient.GetPropertiesOfCertificateVersionsAsync(certificateName))
            {
                if (certVersion.Enabled.HasValue && certVersion.Enabled.Value)
                {
                    properties.Add(certVersion);
                }
            }

            var result = new List<KeyVaultCertificate>();
            foreach (var versionProperties in properties.OrderByDescending(certVersion => certVersion.CreatedOn))
            {
                result.Add(await this._CertificateClient.GetCertificateVersionAsync(versionProperties.Name, versionProperties.Version));
            }

            return result;
        }
        internal async Task<SigningCredentials> GetSigningCredentialsFromCertificateAsync(KeyVaultCertificate certificateItem)
        {
            var certificateVersionSecurityKey = await GetSecurityKeyFromCertificateAsync(certificateItem);
            return new SigningCredentials(certificateVersionSecurityKey.Key, SecurityAlgorithms.RsaSha512);
        }

        internal async Task<SecurityKeyInfo> GetSecurityKeyFromCertificateAsync(KeyVaultCertificate certificateItem)
        {
            var certificateVersionBundle = await this._CertificateClient.GetCertificateAsync(certificateItem.Name);
            var certificatePrivateKeySecretBundle = await this._SecretClient.GetSecretAsync(certificateVersionBundle.Value.Name);
            var privateKeyBytes = Convert.FromBase64String(certificatePrivateKeySecretBundle.Value.Value);
            var certificateWithPrivateKey = new X509Certificate2(privateKeyBytes, (string)null, X509KeyStorageFlags.MachineKeySet);
            return new SecurityKeyInfo()
            {
                Key = new X509SecurityKey(certificateWithPrivateKey),
                SigningAlgorithm = SecurityAlgorithms.RsaSha512
            };
        }
    }
}
