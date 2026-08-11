// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// OWASP A01 / A05 — a deployment whose <c>/.cratis/me</c> endpoint answers with an authorization decision
/// must not admit callers when that decision could not be obtained.
/// <para>
/// The released proxy caught every transport failure, timeout, non-<c>403</c> status, empty body and parse
/// failure and answered them with an empty-but-successful identity, then hard-coded the result to authorized
/// and sealed it into a cookie. So the one moment the proxy knew least about a caller — the backend it asks
/// being down, unreachable, or answering something it could not read — was the moment it was most
/// permissive, and the positive it sealed outlived the outage that produced it.
/// </para>
/// <para>
/// Asserted against a real origin rather than on the client-facing status, because the status is the easy
/// part. What matters is that nothing reached the backend: not the page, and not the static assets a browser
/// fetches straight afterwards, which are the requests a gate placed only on navigation would miss.
/// </para>
/// </summary>
/// <param name="harness">The running proxy whose service requires verification, and its origin.</param>
[Collection(RequiredVerificationSpecCollection.Name)]
public class when_identity_verification_is_required(RequiredVerificationHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _refusedPage;
    string _refusedBody = string.Empty;
    bool _originSawTheProtectedPath;

    HttpResponseMessage? _refusedAsset;
    bool _originSawTheStaticAsset;

    HttpResponseMessage? _admittedPage;
    bool _originSawTheVerifiedCaller;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.FailEveryVerification();

        harness.Origin.Clear();
        _refusedPage = await client.SendAsync(Request(RequiredVerificationHarness.ProtectedPath, "unverified-page"));
        _refusedBody = await _refusedPage.Content.ReadAsStringAsync();
        _originSawTheProtectedPath = harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath);

        harness.Origin.Clear();
        _refusedAsset = await client.SendAsync(Request(RequiredVerificationHarness.StaticAssetPath, "unverified-asset"));
        _originSawTheStaticAsset = harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.StaticAssetPath);

        harness.VerifyEveryCaller();

        harness.Origin.Clear();
        _admittedPage = await client.SendAsync(Request(RequiredVerificationHarness.ProtectedPath, "verified"));
        _originSawTheVerifiedCaller = harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath);
    }

    public Task DisposeAsync()
    {
        harness.VerifyEveryCaller();
        return Task.CompletedTask;
    }

    [Fact]
    public void should_refuse_a_caller_whose_verification_failed() =>
        Assert.Equal(HttpStatusCode.Forbidden, _refusedPage!.StatusCode);

    [Fact]
    public void should_explain_the_refusal_with_the_forbidden_page() =>
        Assert.Contains(RequiredVerificationHarness.ForbiddenMarker, _refusedBody, StringComparison.Ordinal);

    [Fact]
    public void should_forward_nothing_to_the_backend_for_the_protected_route() =>
        Assert.False(_originSawTheProtectedPath, "A caller nobody could verify must not reach the application.");

    [Fact]
    public void should_refuse_the_static_asset_too() =>
        Assert.Equal(HttpStatusCode.Forbidden, _refusedAsset!.StatusCode);

    [Fact]
    public void should_forward_nothing_to_the_backend_for_the_static_asset() =>
        Assert.False(_originSawTheStaticAsset, "A gate only on navigation is not a gate.");

    [Fact]
    public void should_seal_no_authorization_for_a_refused_caller() =>
        Assert.DoesNotContain(
            _refusedPage!.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [],
            cookie => cookie.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal)
                && !cookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void should_admit_the_caller_once_verification_answers_again() =>
        Assert.Equal(HttpStatusCode.OK, _admittedPage!.StatusCode);

    [Fact]
    public void should_forward_the_verified_caller_to_the_backend() =>
        Assert.True(_originSawTheVerifiedCaller, "Restoring the verifier is the only thing that lets a caller through.");

    /// <summary>
    /// Builds an authenticated request from a caller nobody else has used.
    /// </summary>
    /// <param name="path">The path to request.</param>
    /// <param name="hint">A label making the caller recognizable in a failure.</param>
    /// <returns>The request.</returns>
    /// <remarks>
    /// A fresh caller each time because the proxy keeps its answer per user and tenant. A shared identity
    /// would let one request's answer stand in for the next, and every assertion here is about the answer
    /// this request got.
    /// </remarks>
    static HttpRequestMessage Request(string path, string hint) =>
        SecurityHarness.Authenticated(HttpMethod.Get, path, SecurityHarness.UniqueUser(hint));
}
