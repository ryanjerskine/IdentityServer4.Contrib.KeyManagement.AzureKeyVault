using Azure.Core;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityServer4.KeyManagement.AzureKeyVault
{
    public class AzureKeyVaultValidationKeysStore : KeyStore, IValidationKeysStore
    {
        private readonly IMemoryCache _Cache;
        private readonly string _CertificateName;

        public AzureKeyVaultValidationKeysStore(IMemoryCache memoryCache, TokenCredential tokenCredential, string vault, string certificateName) : base(tokenCredential, vault)
        {
            this._Cache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
            this._CertificateName = certificateName ?? throw new ArgumentNullException(nameof(certificateName));
        }

        public async Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
        {
            // Try get the signing credentials from the cache
            if (this._Cache.TryGetValue("ValidationKeys", out List<SecurityKeyInfo> validationKeys))
                return validationKeys;

            validationKeys = new List<SecurityKeyInfo>();

            // Get all the certificate versions (this will also get the currect active version)
            var enabledCertificateVersions = await GetAllEnabledCertificateVersionsAsync(this._CertificateName);
            foreach (var certificateItem in enabledCertificateVersions)
            {
                // Add the security key to validation keys so any JWT tokens signed with a older version of the signing certificate
                validationKeys.Add(await GetSecurityKeyFromCertificateAsync(certificateItem));
            }

            // Add the validation keys to the cache
            var options = new MemoryCacheEntryOptions();
            options.AbsoluteExpiration = DateTime.Now.AddDays(1);
            this._Cache.Set("ValidationKeys", validationKeys, options);

            return validationKeys;
        }
    }
}
