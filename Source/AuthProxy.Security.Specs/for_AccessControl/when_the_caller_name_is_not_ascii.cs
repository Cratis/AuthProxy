// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// OWASP A01 — Broken Access Control, from the other direction: a caller AuthProxy refuses to describe is
/// a caller no backend can authorize, which is a denial of access every bit as total as a wrong policy.
/// <para>
/// A display name is whatever the identity provider says it is, and providers say things like
/// <c>Søren Wærstad</c>. .NET will not write a character above <c>U+007F</c> to a header field — it throws
/// before a byte reaches the socket — so such a person's proxied request failed at the gateway, their
/// <c>/.cratis/me</c> resolution failed silently, and the application did not work for them at all.
/// </para>
/// <para>
/// Only a real socket can show this. An in-memory transform spec passes either way, because
/// <c>HttpRequestMessage.Headers.Add</c> checks for CR, LF and NUL and nothing else — the ASCII refusal
/// happens in the connection, when the request is written. So the assertion is made against a real origin,
/// on stock Kestrel defaults, with no request-header encoding configured anywhere.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_the_caller_name_is_not_ascii(SecurityHarness harness) : IAsyncLifetime
{
    const string Name = "Søren Wærstad";

    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;
    ForwardedRequest? _identityCall;
    ClientPrincipal? _principal;
    string _decodedName = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();

        var request = SecurityHarness.Authenticated(
            HttpMethod.Get,
            SecurityHarness.ProtectedPath,
            SecurityHarness.UniqueUser("non-ascii-name"));
        request.Headers.TryAddWithoutValidation(
            HeaderAuthenticationHandler.EncodedClaimsHeader,
            HeaderAuthenticationHandler.EncodeClaims($"name={Name}"));

        _response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(SecurityHarness.ProtectedPath);
        _identityCall = harness.Origin.LastRequestTo(WellKnownPaths.IdentityDetails);

        if (_forwarded is not null)
        {
            ClientPrincipal.TryFromBase64(_forwarded.Value(Headers.Principal), out _principal);
            HeaderValue.TryDecode(_forwarded.Value(Headers.PrincipalNameExtended), out _decodedName);
        }
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_answer_the_caller() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_reach_the_origin() => Assert.NotNull(_forwarded);
    [Fact] public void should_resolve_identity_details_against_the_origin() => Assert.NotNull(_identityCall);

    [Fact]
    public void should_not_terminate_the_session_over_the_name() =>
        Assert.False(_response!.StatusCode is HttpStatusCode.Found or HttpStatusCode.Unauthorized);

    [Fact]
    public void should_still_send_the_principal_name_header() =>
        Assert.True(_forwarded!.Has(Headers.PrincipalName));

    [Fact]
    public void should_send_only_printable_ascii_on_the_principal_name_header() =>
        Assert.All(_forwarded!.Value(Headers.PrincipalName), character => Assert.InRange(character, ' ', '~'));

    [Fact]
    public void should_announce_the_encoding_with_the_sibling_header() =>
        Assert.True(_forwarded!.Has(Headers.PrincipalNameExtended));

    [Fact]
    public void should_decode_the_sibling_back_to_the_exact_name() =>
        Assert.Equal(Name, _decodedName, StringComparer.Ordinal);

    [Fact]
    public void should_keep_the_exact_name_in_the_client_principal() =>
        Assert.Equal(Name, _principal!.UserDetails, StringComparer.Ordinal);

    [Fact]
    public void should_send_only_printable_ascii_to_the_identity_endpoint() =>
        Assert.All(_identityCall!.Value(Headers.PrincipalName), character => Assert.InRange(character, ' ', '~'));
}
