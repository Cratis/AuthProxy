// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_an_oidc_provider_uses_a_certificate_credential : Specification
{
    OpenIdConnectOptions _options;
    IServiceProvider _services;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Workforce",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.microsoftonline.com/tenant/v2.0",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-id",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientCredential:Source"] = "KeyVaultCertificate",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientCredential:KeyVaultUrl"] = "https://contoso.vault.azure.net",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientCredential:KeyVaultCertificateName"] = "authproxy"
        });

        builder.AddIngressAuthentication();
        _services = builder.Services.BuildServiceProvider();
    }

    void Because() => _options = _services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("workforce");

    [Fact] void should_configure_no_client_secret() => _options.ClientSecret.ShouldBeNull();
    [Fact] void should_authenticate_the_code_redemption() => _options.Events.OnAuthorizationCodeReceived.ShouldNotBeNull();
    [Fact] void should_authenticate_pushed_authorization_requests() => _options.Events.OnPushAuthorization.ShouldNotBeNull();
    [Fact] void should_provide_client_assertions() => _services.GetRequiredService<IOidcClientAssertions>().ShouldBeOfExactType<OidcClientAssertions>();
}
