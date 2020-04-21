using Azure.Core;
using IdentityServer4.Stores;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServer4.KeyManagement.AzureKeyVault
{
    /// <summary>
    /// Extension methods for using Azure Key Vault with <see cref="IIdentityServerBuilder"/>.
    /// </summary>
    public static class IdentityServerAzureKeyVaultConfigurationExtensions
    {
        /// <summary>
        /// Adds a SigningCredentialStore and a ValidationKeysStore that reads the signing certificate from the Azure KeyVault.
        /// </summary>
        /// <param name="identityServerbuilder">The <see cref="IIdentityServerBuilder"/> to add to.</param>
        /// <param name="vault">The Azure KeyVault uri.</param>
        /// <param name="certificateName">The name of the certificate to use as the signing certificate.</param>
        /// <param name="signingKeyRolloverTimeInHours">Key rollover grace period in hours.</param>
        /// <param name="tokenCredential">Azure identity token credential for MSI/AAD use (e.g. Azure.Identity.DefaultAzureCredential).</param>
        /// <returns>The <see cref="IIdentityServerBuilder"/>.</returns>
        public static IIdentityServerBuilder AddSigningCredentialFromAzureKeyVault(this IIdentityServerBuilder identityServerbuilder, string vault, string certificateName, int signingKeyRolloverTimeInHours, TokenCredential tokenCredential)
        {
            identityServerbuilder.Services.AddMemoryCache();

            var sp = identityServerbuilder.Services.BuildServiceProvider();
            identityServerbuilder.Services.AddSingleton<ISigningCredentialStore>(new AzureKeyVaultSigningCredentialStore(sp.GetService<IMemoryCache>(), tokenCredential, vault, certificateName, signingKeyRolloverTimeInHours));
            identityServerbuilder.Services.AddSingleton<IValidationKeysStore>(new AzureKeyVaultValidationKeysStore(sp.GetService<IMemoryCache>(), tokenCredential, vault, certificateName));

            return identityServerbuilder;
        }
    }
}
