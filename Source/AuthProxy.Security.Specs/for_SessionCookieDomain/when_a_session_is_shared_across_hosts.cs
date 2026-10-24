// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SessionCookieDomain;

/// <summary>
/// OWASP A01 — Broken Access Control. A session shared across the hosts of one proxy must still be answered by the
/// service each host routes to: signing in once may carry across hosts, but it must never carry a service's
/// authorization requirements with it.
/// </summary>
/// <param name="harness">The running proxy and its three origins.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_a_session_is_shared_across_hosts(SessionCookieHarness harness) : IAsyncLifetime
{
    IReadOnlyList<string> _signInSetCookies = [];
    HttpResponseMessage? _consoleWithSession;
    bool _consoleSawIt;
    HttpResponseMessage? _chronicleWithSession;
    bool _chronicleSawIt;
    HttpResponseMessage? _operationsWithoutTheClaim;
    bool _operationsSawTheUnqualifiedCaller;
    HttpResponseMessage? _operationsWithTheClaim;
    bool _operationsSawTheQualifiedCaller;
    HttpResponseMessage? _operationsWithoutSession;
    bool _operationsSawTheAnonymousCaller;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var signedIn = await harness.SignIn(client, SessionCookieHarness.ConsoleHost);
        _signInSetCookies = SessionCookieHarness.SetCookies(signedIn);
        var session = SessionCookieHarness.SessionFrom(signedIn);

        harness.ClearOrigins();
        _consoleWithSession = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, "/api/customers", session));
        _consoleSawIt = harness.ConsoleOrigin.ReceivedAnythingFor("/api/customers");

        _chronicleWithSession = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ChronicleHost, "/api/events", session));
        _chronicleSawIt = harness.ChronicleOrigin.ReceivedAnythingFor("/api/events");

        _operationsWithoutTheClaim = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.OperationsHost, "/api/users", session));
        _operationsSawTheUnqualifiedCaller = harness.OperationsOrigin.ReceivedAnythingFor("/api/users");

        harness.ClearOrigins();
        var qualified = SessionCookieHarness.SessionFrom(await harness.SignIn(client, SessionCookieHarness.ConsoleHost, withOperationsClaim: true));
        _operationsWithTheClaim = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.OperationsHost, "/api/users", qualified));
        _operationsSawTheQualifiedCaller = harness.OperationsOrigin.ReceivedAnythingFor("/api/users");

        harness.ClearOrigins();
        _operationsWithoutSession = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.OperationsHost, "/api/users"));
        _operationsSawTheAnonymousCaller = harness.OperationsOrigin.ReceivedAnythingFor("/api/users");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_scope_the_session_cookie_to_the_parent_domain() =>
        Assert.True(
            _signInSetCookies.Any(_ => SessionCookieHarness.IsSettingOf(_, harness.CookieName) && _.Contains($"domain={SessionCookieHarness.Domain}", StringComparison.OrdinalIgnoreCase)),
            string.Join(" || ", _signInSetCookies.Select(_ => _[_.IndexOf(';')..])));

    [Fact]
    public void should_honor_the_session_on_the_host_it_was_issued_for() =>
        Assert.True(_consoleWithSession!.IsSuccessStatusCode && _consoleSawIt);

    [Fact]
    public void should_honor_the_session_on_another_host() =>
        Assert.True(_chronicleWithSession!.IsSuccessStatusCode && _chronicleSawIt);

    [Fact]
    public void should_refuse_the_shared_session_on_a_host_whose_service_requires_a_claim_it_lacks() =>
        Assert.Equal(HttpStatusCode.Forbidden, _operationsWithoutTheClaim!.StatusCode);

    [Fact]
    public void should_not_reach_a_service_whose_requirements_the_session_does_not_meet() =>
        Assert.False(_operationsSawTheUnqualifiedCaller);

    [Fact]
    public void should_forward_a_session_that_meets_the_requirements_of_the_host_it_is_used_on() =>
        Assert.True(_operationsWithTheClaim!.IsSuccessStatusCode && _operationsSawTheQualifiedCaller);

    [Fact]
    public void should_refuse_a_caller_with_no_session_on_any_host() =>
        Assert.Equal(HttpStatusCode.Unauthorized, _operationsWithoutSession!.StatusCode);

    [Fact]
    public void should_not_reach_a_service_with_no_session() =>
        Assert.False(_operationsSawTheAnonymousCaller);
}
