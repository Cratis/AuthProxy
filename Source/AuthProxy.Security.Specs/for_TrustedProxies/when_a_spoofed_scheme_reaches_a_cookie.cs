// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// OWASP A05 — Security Misconfiguration. A spoofed scheme must not reach the <c>Secure</c> flag on a cookie.
/// <para>
/// Eleven places in AuthProxy set a cookie's <c>Secure</c> flag from <c>Request.IsHttps</c>, which forwarded
/// headers decide. The direction that matters is the one asserted here, and it is the quiet one: a caller
/// that can spoof the scheme <em>upward</em> makes an unencrypted deployment mark its cookies <c>Secure</c>,
/// and a browser then silently withholds them — a session that stops working for reasons no log explains. The
/// mirror image is worse and is the same defect: honoring a downward spoof would strip <c>Secure</c> from a
/// session that genuinely is encrypted, leaving it working perfectly and unprotected.
/// </para>
/// <para>
/// The provider-selection cookie is the one probed because it is reachable without a session, and it takes
/// its flag from exactly the same expression as the ten that are not.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_a_spoofed_scheme_reaches_a_cookie(TrustedProxyHarness harness) : IAsyncLifetime
{
    string _setCookie = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var request = TrustedProxyHarness.From(TrustedProxyHarness.UntrustedPeer, TrustedProxyHarness.ProtectedPath);
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "document");

        using var response = await client.SendAsync(request);

        _setCookie = response.Headers.TryGetValues("Set-Cookie", out var values)
            ? string.Join('\n', values.Where(_ => _.StartsWith(Cookies.Providers, StringComparison.Ordinal)))
            : string.Empty;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_issued_the_cookie() => Assert.NotEqual(string.Empty, _setCookie);

    [Fact]
    public void should_not_mark_it_secure_on_an_unencrypted_request() =>
        Assert.DoesNotContain("secure", _setCookie, StringComparison.OrdinalIgnoreCase);
}
