# IdentityServer4.Contrib.KeyManagement.AzureKeyVault

`Install-Package IdentityServer4.Contrib.KeyManagement.AzureKeyVault`

Call .AddSigningCredentialFromAzureKeyVault:
```
using IdentityServer4.KeyManagement.AzureKeyVault;

public void ConfigureServices(IServiceCollection services)
{
  ...
  services.AddIdentityServer()
    .AddSigningCredentialFromAzureKeyVault(Configuration["AzureKeyVault:Url"], "<My Key vault client id>", "<My key vault secret>", "<My Cert Name>", <Signing Key Rollover period in hours>);
  ...
}
```
or if you are using MSI:
```
using IdentityServer4.KeyManagement.AzureKeyVault;

public void ConfigureServices(IServiceCollection services)
{
  ...
  services.AddIdentityServer()
    .AddSigningCredentialFromAzureKeyVault(Configuration["AzureKeyVault:Url"], "<My Cert Name>", <Signing Key Rollover period in hours>);
  ...
}
 ```
This will add all enabled versions of the specified certificate to the ValidationKey set. The current version of the certificate will be used as the signing certificate.
Keys are cached for 24hrs to improve performance. If you are utilizing MSI, make sure it is supported with how you are hosting the application.
