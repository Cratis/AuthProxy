// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SessionCookieDomain;

/// <summary>
/// OWASP A01 — Broken Access Control. The session cookie reaches every host under the domain, including hosts that
/// point at the proxy without being declared. A valid session must not turn such a host into a way to a service.
/// </summary>
/// <param name="harness">The running proxy and its three origins.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_a_session_is_used_on_a_host_no_service_claims(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;
    bool _anyOriginSawIt;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var session = SessionCookieHarness.SessionFrom(await harness.SignIn(client, SessionCookieHarness.ConsoleHost, withOperationsClaim: true));

        harness.ClearOrigins();
        _response = await client.SendAsync(SessionCookieHarness.Request("undeclared.example.test", "/api/users", session));
        _anyOriginSawIt = harness.ConsoleOrigin.ReceivedAnythingFor("/api/users")
            || harness.OperationsOrigin.ReceivedAnythingFor("/api/users")
            || harness.ChronicleOrigin.ReceivedAnythingFor("/api/users");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_route_nothing_that_no_service_claims() =>
        Assert.Equal(HttpStatusCode.NotFound, _response!.StatusCode);

    [Fact]
    public void should_not_reach_any_service() =>
        Assert.False(_anyOriginSawIt);
}
