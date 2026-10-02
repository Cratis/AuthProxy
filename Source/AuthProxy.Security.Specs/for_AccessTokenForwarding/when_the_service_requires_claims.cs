// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.for_AccessTokenForwarding;

/// <summary>
/// Token-forwarding routes must still resolve to the service whose claim requirements authorize the request.
/// </summary>
public class when_the_service_requires_claims : IAsyncLifetime
{
    readonly ClaimHarness _harness = new();
    HttpResponseMessage? _authorized;
    HttpResponseMessage? _denied;
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = _harness.CreateSecurityClient();
        using var authorized = AccessTokenForwardingHarness.FromSession("/api/authorized", "claim-session");
        authorized.Headers.TryAddWithoutValidation(HeaderAuthenticationHandler.ClaimsHeader, "role=member;permission=reports");
        _authorized = await client.SendAsync(authorized);
        _forwarded = _harness.Backend.LastRequestTo("/api/authorized");

        using var denied = AccessTokenForwardingHarness.FromSession("/api/denied", "claim-session");
        denied.Headers.TryAddWithoutValidation(HeaderAuthenticationHandler.ClaimsHeader, "role=member");
        _denied = await client.SendAsync(denied);
    }

    public async Task DisposeAsync()
    {
        _authorized?.Dispose();
        _denied?.Dispose();
        await _harness.DisposeAsync();
    }

    [Fact] public void should_authorize_the_caller_satisfying_root_and_service_requirements() => Assert.Equal(HttpStatusCode.OK, _authorized!.StatusCode);
    [Fact] public void should_forward_the_authorized_callers_bearer_token() => Assert.Equal($"Bearer {AccessTokenForwardingHarness.TokenFor("claim-session")}", _forwarded!.Value("Authorization"));
    [Fact] public void should_deny_a_caller_missing_the_service_claim() => Assert.Equal(HttpStatusCode.Forbidden, _denied!.StatusCode);
    [Fact] public void should_not_forward_the_denied_request() => Assert.False(_harness.Backend.ReceivedAnythingFor("/api/denied"));

    sealed class ClaimHarness : AccessTokenForwardingHarness
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Authorization:RequiredClaims:0:Claim"] = "role",
                [$"{C.AuthProxy.SectionKey}:Authorization:RequiredClaims:0:AnyOf:0"] = "member",
                [$"{C.AuthProxy.SectionKey}:Services:reporting:Authorization:RequiredClaims:0:Claim"] = "permission",
                [$"{C.AuthProxy.SectionKey}:Services:reporting:Authorization:RequiredClaims:0:AnyOf:0"] = "reports",
            }));
        }
    }
}
