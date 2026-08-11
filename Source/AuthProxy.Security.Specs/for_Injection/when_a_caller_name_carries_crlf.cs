// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_Injection;

/// <summary>
/// OWASP A03 — Injection. A display name is attacker-influenced data that AuthProxy copies into a header
/// field, which is the classic shape of response/request splitting: a name containing <c>CRLF</c> followed
/// by <c>x-ms-client-principal-id: attacker</c> would, if it were written literally, hand the origin a
/// second identity header that the proxy never vouched for.
/// <para>
/// The encoder cannot express that. Its output alphabet is the RFC 8187 <c>attr-char</c> set plus
/// <c>%</c>, so CR, LF and NUL have no representation other than an escape — the property is structural
/// rather than a check that could be forgotten. Asserted against a real origin, because the only proof
/// that matters is the set of headers a backend actually received.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_a_caller_name_carries_crlf(SecurityHarness harness) : IAsyncLifetime
{
    const string Name = "victim\r\nx-ms-client-principal-id: attacker";

    readonly string _user = SecurityHarness.UniqueUser("crlf-name");

    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();

        var request = SecurityHarness.Authenticated(HttpMethod.Get, SecurityHarness.ProtectedPath, _user);
        request.Headers.TryAddWithoutValidation(
            HeaderAuthenticationHandler.EncodedClaimsHeader,
            HeaderAuthenticationHandler.EncodeClaims($"name={Name}"));

        await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(SecurityHarness.ProtectedPath);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_still_reach_the_origin() => Assert.NotNull(_forwarded);

    [Fact]
    public void should_not_let_the_name_write_a_principal_id() =>
        Assert.Equal(_user, _forwarded!.Value(Headers.PrincipalId), StringComparer.Ordinal);

    [Fact]
    public void should_not_put_a_line_break_on_the_name_header() =>
        Assert.All(_forwarded!.Value(Headers.PrincipalName), character => Assert.InRange(character, ' ', '~'));

    [Fact]
    public void should_escape_the_line_break_instead() =>
        Assert.Contains("%0D%0A", _forwarded!.Value(Headers.PrincipalName), StringComparison.Ordinal);
}
