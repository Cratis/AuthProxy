// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A machine route backed by a recording origin.
/// </summary>
public class MachineRouteHarness : AccessTokenForwardingHarness
{
    /// <summary>The machine host.</summary>
    public const string Host = "machine.example.test";

    /// <summary>The machine service.</summary>
    public const string Service = "machine";

    /// <summary>The machine client.</summary>
    public const string ClientId = "machine-client";

    /// <summary>The machine route prefix.</summary>
    public const string RoutePrefix = "/api";

    /// <summary>Creates a token for this route.</summary>
    /// <returns>The token.</returns>
    public string MintToken() => Services.GetRequiredService<ClientCredentialsTokenProtector>().CreateToken(
        new ConfiguredClientCredentialsService(Service, RoutePrefix, new Uri($"{Frontend.BaseUrl}/verify")), ClientId, TenantId);

    /// <summary>Creates an authenticated machine request.</summary>
    /// <param name="path">The request path.</param>
    /// <returns>The request.</returns>
    public HttpRequestMessage Request(string path)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {MintToken()}");
        request.Headers.Host = Host;
        request.Headers.TryAddWithoutValidation(Headers.ServiceId, Service);
        return request;
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:reporting:Hosts:0"] = "reporting.example.test",
            [$"{C.AuthProxy.SectionKey}:Services:machine:Hosts:0"] = Host,
            [$"{C.AuthProxy.SectionKey}:Services:machine:Backend:BaseUrl"] = Frontend.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:machine:Frontend:BaseUrl"] = Frontend.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:machine:ResolveIdentityDetails"] = "false",
            [$"{C.AuthProxy.SectionKey}:Services:machine:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
            [$"{C.AuthProxy.SectionKey}:Services:machine:ClientCredentials:RoutePrefix"] = RoutePrefix
        }));
        builder.ConfigureTestServices(services => services.PostConfigure<AuthenticationOptions>(options =>
        {
            options.DefaultScheme = ClientCredentialsDefaults.CompositeAuthenticationScheme;
            options.DefaultChallengeScheme = ClientCredentialsDefaults.AuthenticationScheme;
        }));
    }
}
