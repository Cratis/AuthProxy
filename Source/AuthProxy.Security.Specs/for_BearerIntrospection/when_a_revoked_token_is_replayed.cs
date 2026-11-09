// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerIntrospection;

/// <summary>
/// Signature validation cannot know a token was revoked; asking the issuer can. A token the issuer reports inactive
/// is refused as an invalid token on every replay, never forwarded, and the refusal is not remembered: once the
/// issuer says the token is active again, the next request goes through.
/// </summary>
/// <param name="harness">The running proxy, origin, issuer and introspection endpoint.</param>
[Collection(IntrospectionSpecCollection.Name)]
public class when_a_revoked_token_is_replayed(IntrospectionHarness harness) : IAsyncLifetime
{
    const string Path = $"{IntrospectionHarness.MarkedRoute}/tools";

    HttpStatusCode _whileActive;
    HttpStatusCode _afterRevocation;
    HttpStatusCode _replayed;
    HttpStatusCode _afterReactivation;
    string _challenge = string.Empty;
    bool _forwardedAfterRevocation;
    int _callsBeforeReactivation;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Endpoint.Reset();
        var token = harness.Issuer.Token();

        harness.Endpoint.Activate(token);
        _whileActive = (await Send(client, token)).StatusCode;

        harness.Endpoint.Revoke(token);
        harness.Origin.Clear();
        using var revoked = await Send(client, token);
        _afterRevocation = revoked.StatusCode;
        _challenge = revoked.Headers.WwwAuthenticate.ToString();
        _forwardedAfterRevocation = harness.Origin.ReceivedAnythingFor(Path);
        _replayed = (await Send(client, token)).StatusCode;
        _callsBeforeReactivation = harness.Endpoint.CallsTo(StubIntrospectionEndpoint.Path);

        harness.Endpoint.Activate(token);
        _afterReactivation = (await Send(client, token)).StatusCode;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_forward_while_the_issuer_reports_the_token_active() => Assert.Equal(HttpStatusCode.OK, _whileActive);
    [Fact] public void should_refuse_once_the_issuer_reports_it_inactive() => Assert.Equal(HttpStatusCode.Unauthorized, _afterRevocation);
    [Fact] public void should_challenge_as_an_invalid_token() => Assert.Contains("invalid_token", _challenge);
    [Fact] public void should_not_forward_the_request() => Assert.False(_forwardedAfterRevocation);
    [Fact] public void should_refuse_every_replay() => Assert.Equal(HttpStatusCode.Unauthorized, _replayed);
    [Fact] public void should_ask_the_issuer_again_on_every_replay() => Assert.Equal(3, _callsBeforeReactivation);
    [Fact] public void should_honor_the_token_at_once_when_the_issuer_reports_it_active_again() => Assert.Equal(HttpStatusCode.OK, _afterReactivation);

    static async Task<HttpResponseMessage> Send(HttpClient client, string token) =>
        await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, token));
}
