using IdentityServer4.Models;
using Microsoft.Azure.KeyVault;
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
        private readonly KeyVaultClient _KeyVaultClient;
        private readonly string _Vault;

        public KeyStore(KeyVaultClient keyVaultClient, string vault)
        {
            this._KeyVaultClient = keyVaultClient ?? throw new ArgumentNullException(nameof(keyVaultClient));
            this._Vault = vault ?? throw new ArgumentNullException(nameof(vault));
        }

        internal async Task<List<Microsoft.Azure.KeyVault.Models.CertificateItem>> GetAllEnabledCertificateVersionsAsync(string certificateName)
        {
            // Get all the certificate versions (this will also get the currect active version)
            var certificateVersions = await this._KeyVaultClient.GetCertificateVersionsAsync(this._Vault, certificateName);

            // Find all enabled versions of the certificate and sort them by creation date in decending order 
            return certificateVersions
              .Where(certVersion => certVersion.Attributes.Enabled.HasValue && certVersion.Attributes.Enabled.Value)
              .OrderByDescending(certVersion => certVersion.Attributes.Created)
              .ToList();
        }
        internal async Task<SigningCredentials> GetSigningCredentialsFromCertificateAsync(Microsoft.Azure.KeyVault.Models.CertificateItem certificateItem)
        {
            var certificateVersionSecurityKey = await GetSecurityKeyFromCertificateAsync(certificateItem);
            return new SigningCredentials(certificateVersionSecurityKey.Key, SecurityAlgorithms.RsaSha512);
        }
        internal async Task<SecurityKeyInfo> GetSecurityKeyFromCertificateAsync(Microsoft.Azure.KeyVault.Models.CertificateItem certificateItem)
        {
            var certificateVersionBundle = await this._KeyVaultClient.GetCertificateAsync(certificateItem.Identifier.Identifier);
            var certificatePrivateKeySecretBundle = await this._KeyVaultClient.GetSecretAsync(certificateVersionBundle.SecretIdentifier.Identifier);
            var privateKeyBytes = Convert.FromBase64String(certificatePrivateKeySecretBundle.Value);
            var certificateWithPrivateKey = new X509Certificate2(privateKeyBytes, (string)null, X509KeyStorageFlags.MachineKeySet);
            return new SecurityKeyInfo()
            {
                Key = new X509SecurityKey(certificateWithPrivateKey),
                SigningAlgorithm = SecurityAlgorithms.RsaSha512
            };
        }
    }
}
