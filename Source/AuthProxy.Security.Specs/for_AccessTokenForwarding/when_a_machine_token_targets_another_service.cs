// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.for_AccessTokenForwarding;

/// <summary>
/// A real AuthProxy machine token must not authenticate another service's token-forwarding backend, even with
/// caller-supplied service selection or only one client-credentials candidate and no claim authorization gate.
/// </summary>
public class when_a_machine_token_targets_another_service
{
    [Theory]
    [InlineData("/api/host", null, "/api")]
    [InlineData("/reports/api/header", "machine", "/reports/api")]
    [InlineData("/reports/api/query?service=machine", null, "/reports/api")]
    public async Task should_reject_the_token_without_reaching_the_other_backend(string path, string? service, string routePrefix)
    {
        await using var harness = new MachineHarness(routePrefix);
        using var client = harness.CreateSecurityClient();
        var token = harness.Services.GetRequiredService<ClientCredentialsTokenProtector>().CreateToken(
            new ConfiguredClientCredentialsService("machine", routePrefix, new Uri($"{harness.Frontend.BaseUrl}/verify")),
            "machine-client",
            AccessTokenForwardingHarness.TenantId);

        // Prove the bearer token and the real authentication handler work for its own service first.
        var controlPath = $"{routePrefix}/control";
        using var control = new HttpRequestMessage(HttpMethod.Get, controlPath);
        control.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        control.Headers.Host = "machine.example.test";
        control.Headers.TryAddWithoutValidation(Headers.ServiceId, "machine");
        using var controlResponse = await client.SendAsync(control);
        Assert.Equal(HttpStatusCode.OK, controlResponse.StatusCode);
        Assert.NotNull(harness.Frontend.LastRequestTo(controlPath));

        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        request.Headers.Host = "reporting.example.test";
        if (service is not null)
        {
            request.Headers.TryAddWithoutValidation(Headers.ServiceId, service);
        }

        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(harness.Backend.ReceivedAnythingFor(path.Split('?')[0]));
    }

    sealed class MachineHarness(string routePrefix) : AccessTokenForwardingHarness
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:reporting:Hosts:0"] = "reporting.example.test",
                [$"{C.AuthProxy.SectionKey}:Services:prefixed:PathPrefix"] = "/reports",
                [$"{C.AuthProxy.SectionKey}:Services:prefixed:Hosts:0"] = "reporting.example.test",
                [$"{C.AuthProxy.SectionKey}:Services:prefixed:Backend:BaseUrl"] = Backend.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:prefixed:ResolveIdentityDetails"] = "false",
                [$"{C.AuthProxy.SectionKey}:Services:prefixed:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
                [$"{C.AuthProxy.SectionKey}:Services:prefixed:AccessToken:Scopes:0"] = "api://reporting/access_as_user",
                [$"{C.AuthProxy.SectionKey}:Services:machine:Backend:BaseUrl"] = Frontend.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:machine:Frontend:BaseUrl"] = Frontend.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:machine:ResolveIdentityDetails"] = "false",
                [$"{C.AuthProxy.SectionKey}:Services:machine:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
                [$"{C.AuthProxy.SectionKey}:Services:machine:ClientCredentials:RoutePrefix"] = routePrefix,
            }));
            builder.ConfigureTestServices(services => services.PostConfigure<AuthenticationOptions>(options =>
            {
                options.DefaultScheme = ClientCredentialsDefaults.CompositeAuthenticationScheme;
                options.DefaultChallengeScheme = ClientCredentialsDefaults.AuthenticationScheme;
            }));
        }
    }
}
