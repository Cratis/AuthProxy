// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// A deployment that does not sign forwards no assertion at all, and in particular never passes on one a caller
/// wrote: a backend that verifies must not be handed a forged assertion by a proxy that was never asked to sign.
/// </summary>
/// <param name="harness">The running unsigned proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_signing_is_not_configured(SecurityHarness harness) : IAsyncLifetime
{
    const string Path = "/api/unsigned";
    const string Forged = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.forged";

    ForwardedRequest? _session;
    ForwardedRequest? _anonymous;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();

        var session = SecurityHarness.Authenticated(HttpMethod.Get, Path, SecurityHarness.UniqueUser("unsigned"));
        session.Headers.TryAddWithoutValidation(Headers.ForwardedIdentity, Forged);
        using var sessionResponse = await client.SendAsync(session);
        _session = harness.Origin.LastRequestTo(Path);

        var anonymous = SecurityHarness.Anonymous(HttpMethod.Get, SecurityHarness.AnonymousPath);
        anonymous.Headers.TryAddWithoutValidation(Headers.ForwardedIdentity, Forged);
        using var anonymousResponse = await client.SendAsync(anonymous);
        _anonymous = harness.Origin.LastRequestTo(SecurityHarness.AnonymousPath);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_session_request() => Assert.NotNull(_session);
    [Fact] public void should_not_forward_an_assertion_with_the_session_request() => Assert.False(_session!.Has(Headers.ForwardedIdentity));
    [Fact] public void should_forward_the_anonymous_request() => Assert.NotNull(_anonymous);
    [Fact] public void should_not_forward_an_assertion_with_the_anonymous_request() => Assert.False(_anonymous!.Has(Headers.ForwardedIdentity));
}
