// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A real session and client-credentials deployment with a controlled clock.</summary>
public class CredentialSelectionHarness : RequiredVerificationHarness
{
    /// <summary>The tenant of the client-credentials token, distinct from the browser tenant.</summary>
    public const string TokenTenant = "22222222-2222-2222-2222-222222222222";

    /// <summary>Gets the clock used by authentication.</summary>
    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

    /// <summary>Creates an access token for the configured service.</summary>
    /// <returns>The protected access token.</returns>
    public string Token() => Services.GetRequiredService<ClientCredentialsTokenProtector>().CreateToken(
        new ConfiguredClientCredentialsService("app", ProtectedPath, new Uri(Origin.BaseUrl)), "service-client", TokenTenant);

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Clock);
            services.PostConfigure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, options => options.TimeProvider = Clock);
        }).ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:app:ClientCredentials:RoutePrefix"] = ProtectedPath,
            [$"{C.AuthProxy.SectionKey}:Services:app:ClientCredentials:VerificationPath"] = "/verify",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Claim),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:ClaimType"] = ClientCredentialsDefaults.TenantClaimType,
            [$"{C.AuthProxy.SectionKey}:Tenants:{TokenTenant}:SourceIdentifiers:0"] = TokenTenant,
        }));
    }
}
