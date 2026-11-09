// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json;

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>
/// A caller-supplied authentication time, in a header, in a forged principal and as a provider claim, never reaches
/// the backend: only a time AuthProxy recorded for the session is forwarded, and then only inside the signed principal.
/// </summary>
/// <param name="harness">The running signed proxy.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_hostile_authentication_time_reaches_a_signed_browser_route(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    const string Fake = "9999999999";
    ForwardedIdentityObservation[] _requests = [];
    HttpStatusCode _status;

    public async ValueTask InitializeAsync()
    {
        harness.ApplicationOrigin.Received.Clear();
        using var client = harness.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/api/hostile");
        var forged = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $$"""{"identityProvider":"caller-forged","userId":"caller-forged","userDetails":"caller-forged","userRoles":["Administrator"],"claims":[{"type":"auth_time","value":"{{Fake}}"}]}"""));
        request.Headers.TryAddWithoutValidation(Headers.Principal, forged);
        request.Headers.TryAddWithoutValidation("x-cratis-auth-time", Fake);
        request.Headers.TryAddWithoutValidation("X-CRATIS-AUTH-TIME", Fake);
        request.Headers.TryAddWithoutValidation("x-ms-client-principal-auth-time", Fake);

        // The spec authenticator turns this (test-only, not an identity header) into a provider-supplied auth_time claim.
        request.Headers.TryAddWithoutValidation(HeaderAuthenticationHandler.ClaimsHeader, $"auth_time={Fake}");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        _status = response.StatusCode;
        _requests = harness.ApplicationOrigin.Received.ToArray();
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_forward_the_request() => Assert.Equal(HttpStatusCode.OK, _status);
    [Fact] public void should_not_forward_an_authentication_time_header() => Assert.All(_requests, request => Assert.DoesNotContain(request.Headers.Keys, key => key.Contains("auth-time", StringComparison.OrdinalIgnoreCase)));
    [Fact] public void should_not_forward_the_fake_value_anywhere() => Assert.All(_requests, request => Assert.DoesNotContain(request.Headers.Where(header => !string.Equals(header.Key, HeaderAuthenticationHandler.ClaimsHeader, StringComparison.OrdinalIgnoreCase)).SelectMany(header => header.Value), value => value.Contains(Fake, StringComparison.Ordinal)));
    [Fact] public void should_not_forward_an_authentication_time_inside_the_principal() => Assert.All(_requests.Where(request => request.Headers.ContainsKey(Headers.Principal)), request => Assert.DoesNotContain("auth_time", Decode(request.Headers[Headers.Principal].Single()), StringComparison.Ordinal));
    [Fact] public void should_verify_every_identity_bearing_hop() => Assert.All(_requests, request => Assert.True(request.Verified));

    static string Decode(string principal) => JsonDocument.Parse(Convert.FromBase64String(principal)).RootElement.GetRawText();
}
