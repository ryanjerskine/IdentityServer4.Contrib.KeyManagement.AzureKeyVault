using IdentityServer4.Stores;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.KeyManagement.AzureKeyVault
{
    public class AzureKeyVaultSigningCredentialStore : KeyStore, ISigningCredentialStore
    {
        private readonly IMemoryCache _Cache;
        private readonly string _CertificateName;
        private readonly int _SigningKeyRolloverTimeInHours;

        public AzureKeyVaultSigningCredentialStore(IMemoryCache memoryCache, KeyVaultClient keyVaultClient, string vault, string certificateName, int signingKeyRolloverTimeInHours) : base(keyVaultClient, vault)
        {
            this._Cache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            this._CertificateName = certificateName ?? throw new ArgumentNullException(nameof(certificateName));
            this._SigningKeyRolloverTimeInHours = signingKeyRolloverTimeInHours;
        }

        public async Task<SigningCredentials> GetSigningCredentialsAsync()
        {
            // Try get the signing credentials from the cache
            if (this._Cache.TryGetValue("SigningCredentials", out SigningCredentials signingCredentials))
                return signingCredentials;

            signingCredentials = await GetFirstValidSigningCredentials();

            if (signingCredentials == null)
                return null;

            // Cache it
            var options = new MemoryCacheEntryOptions();
            options.AbsoluteExpiration = DateTime.Now.AddDays(1);
            this._Cache.Set("SigningCredentials", signingCredentials, options);

            return signingCredentials;
        }

        private async Task<SigningCredentials> GetFirstValidSigningCredentials()
        {
            // Find all enabled versions of the certificate
            var enabledCertificateVersions = await GetAllEnabledCertificateVersionsAsync(this._CertificateName);

            if (!enabledCertificateVersions.Any())
                return null;

            // Find the first certificate version that has a passed rollover time
            var certificateVersionWithPassedRolloverTime = enabledCertificateVersions
              .FirstOrDefault(certVersion => certVersion.Attributes.Created.HasValue && certVersion.Attributes.Created.Value < DateTime.UtcNow.AddHours(-this._SigningKeyRolloverTimeInHours));

            // If no certificate with passed rollovertime was found, pick the first enabled version of the certificate (This can happen if it's a newly created certificate)
            if (certificateVersionWithPassedRolloverTime == null)
                return await GetSigningCredentialsFromCertificateAsync(enabledCertificateVersions.First());
            else
                return await GetSigningCredentialsFromCertificateAsync(certificateVersionWithPassedRolloverTime);
        }
    }
}
