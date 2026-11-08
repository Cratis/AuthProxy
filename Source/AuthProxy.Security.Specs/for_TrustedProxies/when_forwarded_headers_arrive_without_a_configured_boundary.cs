// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>Default-mode requests retain the connection's address and scheme, including downstream decisions.</summary>
/// <param name="harness">A proxy with no trusted proxies configured.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_forwarded_headers_arrive_without_a_configured_boundary(SecurityHarness harness)
{
    [Theory]
    [InlineData("198.51.100.10", false)]
    [InlineData("10.0.0.7", true)]
    public async Task should_ignore_forwarded_values_for_public_and_private_peers(string peer, bool confusing)
    {
        using var client = harness.CreateSecurityClient();
        using var request = TrustedProxyHarness.From(peer, SecurityHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", confusing ? "203.0.113.9, , 10.0.0.1" : "203.0.113.9");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", confusing ? "https, http" : "https");
        request.Headers.TryAddWithoutValidation("Forwarded", "for=203.0.113.9;proto=https");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(peer, harness.Observations.Last!.RemoteIpAddress);
        Assert.Equal("http", harness.Observations.Last.Scheme);
        Assert.True(harness.Logs.Mentioning("received but ignored", "Cratis:AuthProxy:Ingress:TrustedProxies"));
    }

    [Fact]
    public async Task should_not_make_a_cookie_secure_from_forwarded_proto()
    {
        using var client = harness.CreateSecurityClient();
        using var request = SecurityHarness.Anonymous(HttpMethod.Get, WellKnownPaths.LoginPage + "?reason=remote-failure");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "document");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), value =>
            value.StartsWith(Cookies.Providers, StringComparison.Ordinal));

        Assert.DoesNotContain("; secure", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task should_not_add_a_forwarded_scheme_to_the_logout_allow_list()
    {
        using var client = harness.CreateSecurityClient();
        using var request = SecurityHarness.Anonymous(HttpMethod.Get, "/.cratis/logout?redirect=https%3A%2F%2Flocalhost%2Fafter-logout");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(PostLogoutRedirectPolicy.ApplicationRoot, response.Headers.Location?.ToString());
    }
}
