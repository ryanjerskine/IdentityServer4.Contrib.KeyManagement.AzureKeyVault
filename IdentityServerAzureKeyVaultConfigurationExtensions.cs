using IdentityServer4.Stores;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Threading.Tasks;

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
        /// <param name="clientId">The application client id.</param>
        /// <param name="clientSecret">The client secret to use for authentication.</param>
        /// <param name="certificateName">The name of the certificate to use as the signing certificate.</param>
        /// <returns>The <see cref="IIdentityServerBuilder"/>.</returns>
        public static IIdentityServerBuilder AddSigningCredentialFromAzureKeyVault(this IIdentityServerBuilder identityServerbuilder, string vault, string clientId, string clientSecret, string certificateName, int signingKeyRolloverTimeInHours)
        {
            KeyVaultClient.AuthenticationCallback authenticationCallback = (authority, resource, scope) => GetTokenFromClientSecret(authority, resource, clientId, clientSecret);
            var keyVaultClient = new KeyVaultClient(authenticationCallback);

            identityServerbuilder.Services.AddMemoryCache();

            var sp = identityServerbuilder.Services.BuildServiceProvider();
            identityServerbuilder.Services.AddSingleton<ISigningCredentialStore>(new AzureKeyVaultSigningCredentialStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName, signingKeyRolloverTimeInHours));
            identityServerbuilder.Services.AddSingleton<IValidationKeysStore>(new AzureKeyVaultValidationKeysStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName));

            return identityServerbuilder;
        }

        /// <summary>
        /// Adds a SigningCredentialStore and a ValidationKeysStore that reads the signing certificate from the Azure KeyVault.
        /// </summary>
        /// <param name="identityServerbuilder">The <see cref="IIdentityServerBuilder"/> to add to.</param>
        /// <param name="vault">The Azure KeyVault uri.</param>
        /// <param name="certificateName">The name of the certificate to use as the signing certificate.</param>
        /// <remarks>Use this if you are using MSI (Managed Service Identity)</remarks>
        /// <returns>The <see cref="IIdentityServerBuilder"/>.</returns>
        public static IIdentityServerBuilder AddSigningCredentialFromAzureKeyVault(this IIdentityServerBuilder builder, string vault, string certificateName, int signingKeyRolloverTimeInHours)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
            var keyVaultClient = new KeyVaultClient(authenticationCallback);

            builder.Services.AddMemoryCache();

            var sp = builder.Services.BuildServiceProvider();
            builder.Services.AddSingleton<ISigningCredentialStore>(new AzureKeyVaultSigningCredentialStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName, signingKeyRolloverTimeInHours));
            builder.Services.AddSingleton<IValidationKeysStore>(new AzureKeyVaultValidationKeysStore(sp.GetService<IMemoryCache>(), keyVaultClient, vault, certificateName));

            return builder;
        }

        private static async Task<string> GetTokenFromClientSecret(string authority, string resource, string clientId, string clientSecret)
        {
            var authContext = new AuthenticationContext(authority);
            var clientCred = new ClientCredential(clientId, clientSecret);
            var result = await authContext.AcquireTokenAsync(resource, clientCred);
            return result.AccessToken;
        }
    }
}
