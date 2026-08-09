// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// OWASP A01 — Broken Access Control. A deployment that declares a required claim must actually refuse the
/// callers that lack it, and must refuse them before anything behind the proxy is touched.
/// <para>
/// This is the whole reason first-gate authorization exists. AuthProxy authenticates against providers
/// that will happily verify anyone — a public GitHub account is a real, verified identity — so on a public
/// host "signed in" and "allowed" are not the same statement, and a proxy that only makes the first one
/// admits the internet.
/// </para>
/// <para>
/// Asserted against a real origin rather than on the client-facing status, because the status is the part
/// that is easy to get right. The refusal is only worth anything if nothing reached the backend: the
/// request itself, obviously, but also the proxy's own <c>/.cratis/me</c> identity call, which runs later
/// in the pipeline and would otherwise mean a refused caller still caused work — and a log entry — inside
/// the application.
/// </para>
/// </summary>
/// <param name="harness">The running claim-gated proxy and its origin.</param>
[Collection(ClaimGateSpecCollection.Name)]
public class when_a_claim_gate_is_configured(ClaimGatedHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _unqualified;
    string _unqualifiedBody = string.Empty;
    bool _originSawTheUnqualifiedCaller;

    HttpResponseMessage? _qualified;
    bool _originSawTheQualifiedCaller;

    HttpResponseMessage? _anonymousOnAnonymousPath;
    bool _originSawTheAnonymousCaller;

    HttpResponseMessage? _unqualifiedOnAnonymousPath;
    bool _originSawTheUnqualifiedCallerOnTheAnonymousPath;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();
        _unqualified = await client.SendAsync(ClaimGatedHarness.Unqualified(ClaimGatedHarness.ProtectedPath));
        _unqualifiedBody = await _unqualified.Content.ReadAsStringAsync();
        _originSawTheUnqualifiedCaller = !harness.Origin.Received.IsEmpty;

        harness.Origin.Clear();
        _qualified = await client.SendAsync(ClaimGatedHarness.Qualified(ClaimGatedHarness.ProtectedPath));
        _originSawTheQualifiedCaller = harness.Origin.ReceivedAnythingFor(ClaimGatedHarness.ProtectedPath);

        harness.Origin.Clear();
        _anonymousOnAnonymousPath = await client.SendAsync(SecurityHarness.Anonymous(HttpMethod.Get, ClaimGatedHarness.AnonymousPath));
        _originSawTheAnonymousCaller = harness.Origin.ReceivedAnythingFor(ClaimGatedHarness.AnonymousPath);

        harness.Origin.Clear();
        _unqualifiedOnAnonymousPath = await client.SendAsync(ClaimGatedHarness.Unqualified(ClaimGatedHarness.AnonymousPath));
        _originSawTheUnqualifiedCallerOnTheAnonymousPath = harness.Origin.ReceivedAnythingFor(ClaimGatedHarness.AnonymousPath);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_refuse_an_authenticated_caller_without_the_required_claim() =>
        Assert.Equal(HttpStatusCode.Forbidden, _unqualified!.StatusCode);

    [Fact]
    public void should_explain_the_refusal_with_the_not_authorized_page() =>
        Assert.Contains(ClaimGatedHarness.NotAuthorizedMarker, _unqualifiedBody, StringComparison.Ordinal);

    [Fact]
    public void should_offer_the_refused_caller_a_way_to_sign_out() =>
        Assert.Contains(WellKnownPaths.Logout, _unqualifiedBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_redirect_the_refused_caller_back_into_a_sign_in_loop() =>
        Assert.False(_unqualified!.Headers.Location is not null);

    [Fact]
    public void should_let_nothing_at_all_reach_the_origin_for_a_refused_caller() =>
        Assert.False(_originSawTheUnqualifiedCaller);

    [Fact]
    public void should_forward_an_authenticated_caller_carrying_the_required_claim() =>
        Assert.Equal(HttpStatusCode.OK, _qualified!.StatusCode);

    [Fact]
    public void should_let_the_qualified_caller_reach_the_origin() =>
        Assert.True(_originSawTheQualifiedCaller);

    [Fact]
    public void should_not_gate_a_declared_anonymous_path_for_a_caller_with_no_session() =>
        Assert.True(_originSawTheAnonymousCaller);

    [Fact]
    public void should_answer_the_anonymous_path_from_the_origin() =>
        Assert.Equal(HttpStatusCode.OK, _anonymousOnAnonymousPath!.StatusCode);

    [Fact]
    public void should_not_gate_a_declared_anonymous_path_for_a_signed_in_caller_who_lacks_the_claim() =>
        Assert.True(_originSawTheUnqualifiedCallerOnTheAnonymousPath);

    [Fact]
    public void should_answer_the_anonymous_path_for_that_caller_too() =>
        Assert.Equal(HttpStatusCode.OK, _unqualifiedOnAnonymousPath!.StatusCode);
}
