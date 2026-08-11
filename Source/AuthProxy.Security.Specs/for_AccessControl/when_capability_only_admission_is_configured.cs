// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// OWASP A01 — Broken Access Control, and A05 — Security Misconfiguration. A deployment that answers
/// nothing until a capability admits must let nothing at all through, and must let nothing at all reach the
/// application while it refuses.
/// <para>
/// The claim gate answers a different question and deliberately passes an unauthenticated caller straight
/// through, so on a public host AuthProxy still answers the internet: it lists the configured providers,
/// confirms whether a named one exists, serves the selection page and its assets, and honors whatever paths
/// a service declared anonymous. Every one of those is an answer to somebody who has presented nothing, and
/// together they say an AuthProxy is here, which organization's providers it trusts and which paths it will
/// forward without a session.
/// </para>
/// <para>
/// Asserted against a real origin rather than on the client-facing status. A <c>404</c> that still caused a
/// forwarded request, or still caused the proxy's own <c>/.cratis/me</c> call, is a refusal that did work
/// and wrote a log line inside the application on behalf of a caller who was refused — and the declared
/// anonymous path is the pointed case, because that is the one route which normally reaches the backend
/// with no session at all.
/// </para>
/// </summary>
/// <param name="harness">The running closed proxy and its origin.</param>
[Collection(CapabilityOnlySpecCollection.Name)]
public class when_capability_only_admission_is_configured(CapabilityOnlyHarness harness) : IAsyncLifetime
{
    /// <summary>
    /// Every route this deployment could answer, ordered so the first probe is one the pipeline can answer
    /// without an authentication handler.
    /// </summary>
    /// <remarks>
    /// All of them are meant to be refused before they reach anything. But if the gate ever stops refusing,
    /// <c>/.cratis/login/provider-one</c> reaches <c>ChallengeAsync</c> for a scheme this harness deliberately
    /// replaced and throws — which errors the whole class with "No authentication handler is registered", a
    /// message about the harness rather than about the gate. Leading with the provider list makes the first
    /// thing that goes wrong a recorded answer that differs, which is the actual finding.
    /// </remarks>
    static readonly string[] _routes =
    [
        WellKnownPaths.Providers,
        CapabilityOnlyHarness.ProtectedPath,
        CapabilityOnlyHarness.AnonymousPath,
        WellKnownPaths.Token,
        WellKnownPaths.LoginPage,
        WellKnownPaths.Logout,
        "/signin-github",
        WellKnownPaths.Registration,
        "/invite/eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIxIn0.c2ln",
        $"{WellKnownPaths.LoginPrefix}/provider-one",
    ];

    readonly List<string> _shapes = [];
    readonly List<string> _originSaw = [];

    HttpStatusCode _admittedStatus;
    bool _originSawTheAdmittedCaller;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        foreach (var route in _routes)
        {
            harness.Origin.Clear();

            _shapes.Add(await ShapeOf(client, SecurityHarness.Anonymous(HttpMethod.Get, route)));
            _shapes.Add(await ShapeOf(
                client,
                SecurityHarness.Authenticated(HttpMethod.Get, route, SecurityHarness.UniqueUser("capability-only"))));

            if (!harness.Origin.Received.IsEmpty)
            {
                _originSaw.Add(route);
            }
        }

        harness.Origin.Clear();
        var entryTransaction = await CapabilityOnlyHarness.Admit(client);
        _originSawTheAdmittedCaller = !harness.Origin.Received.IsEmpty;

        using var admitted = SecurityHarness.Authenticated(
            HttpMethod.Get,
            CapabilityOnlyHarness.ProtectedPath,
            SecurityHarness.UniqueUser("capability-only-admitted"));
        admitted.Headers.TryAddWithoutValidation("Cookie", $"{Cookies.EntryTransaction}={entryTransaction}");

        using var response = await client.SendAsync(admitted);
        _admittedStatus = response.StatusCode;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Records what one probe answered, treating a request the pipeline threw on as a shape of its own.
    /// </summary>
    /// <param name="client">The client to probe with.</param>
    /// <param name="request">The request to send.</param>
    /// <returns>The observed shape.</returns>
    /// <remarks>
    /// A refused request never reaches anything that can throw. One that does reach it is already the
    /// finding, so it is recorded as a shape that differs from every refusal rather than allowed to abort
    /// the class with an exception about whatever it happened to reach first.
    /// </remarks>
    static async Task<string> ShapeOf(HttpClient client, HttpRequestMessage request)
    {
        using (request)
        {
            try
            {
                using var response = await client.SendAsync(request);

                return $"{(int)response.StatusCode}|{await response.Content.ReadAsStringAsync()}";
            }
            catch (Exception exception)
            {
                return $"threw|{exception.GetType().Name}: {exception.Message}";
            }
        }
    }

    [Fact]
    public void should_answer_every_route_the_same_way_whether_or_not_the_caller_has_a_session() =>
        Assert.Single(_shapes.Distinct(StringComparer.Ordinal));

    [Fact]
    public void should_refuse_every_route() =>
        Assert.StartsWith("404|", _shapes[0], StringComparison.Ordinal);

    [Fact]
    public void should_let_nothing_at_all_reach_the_origin() =>
        Assert.Empty(_originSaw);

    [Fact]
    public void should_not_call_the_verifier_through_the_origin() =>
        Assert.False(_originSawTheAdmittedCaller);

    [Fact]
    public void should_let_an_admitted_and_authenticated_caller_through() =>
        Assert.Equal(HttpStatusCode.OK, _admittedStatus);
}
