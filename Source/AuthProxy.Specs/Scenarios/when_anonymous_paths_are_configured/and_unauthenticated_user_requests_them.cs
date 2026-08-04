// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// End-to-end scenario: an unauthenticated user requests the declared anonymous paths, and an
/// undeclared one, with two providers configured.
/// <para>
/// The declared paths must get all the way to the reverse proxy — past
/// <see cref="Authentication.SelectProviderMiddleware"/> and past the authorization policy on the
/// generated route. The test destinations do not exist, so reaching the forwarder surfaces as a
/// <c>502 Bad Gateway</c>; that is the assertion's whole point — it can only be produced by a request
/// that was forwarded. An undeclared path must be unaffected and still receive the selection page, which
/// is what proves the prefixes do not over-match.
/// </para>
/// <para>
/// The declared paths are requested without any fetch metadata or <c>Accept</c> header — the shape a
/// webhook or a bare client sends, and the shape that is otherwise refused outright. Getting them
/// forwarded is what pins the ordering: the declared-path skip has to be reached before the caller is
/// ever classified, or declaring a path anonymous would open it to browsers only.
/// </para>
/// <para>
/// This factory resolves a fixed tenant for every request, so <c>TenancyMiddleware</c>'s refusal branch is
/// never entered here — that third enforcement point is covered by
/// <see cref="and_the_tenant_cannot_be_resolved"/>.
/// </para>
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_unauthenticated_user_requests_them(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _declaredFrontend;
    HttpResponseMessage? _declaredFrontendChild;
    HttpResponseMessage? _declaredFrontendInDifferentCasing;
    HttpResponseMessage? _declaredBackend;
    HttpResponseMessage? _undeclared;
    HttpResponseMessage? _undeclaredSibling;
    HttpResponseMessage? _undeclaredLongerFirstSegment;
    string? _undeclaredBody;
    string? _undeclaredSiblingBody;
    string? _undeclaredLongerFirstSegmentBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();

        _declaredFrontend = await client.GetAsync(AuthProxyFactory.AnonymousFrontendPath);
        _declaredFrontendChild = await client.GetAsync($"{AuthProxyFactory.AnonymousFrontendPath}/some-token");
        _declaredBackend = await client.GetAsync(AuthProxyFactory.AnonymousBackendPath);

        // The route table matches literal segments case-insensitively whatever the middlewares decide,
        // so the middlewares have to agree — this is the request that would split them if they did not.
        _declaredFrontendInDifferentCasing = await client.GetAsync(AuthProxyFactory.AnonymousFrontendPath.ToUpperInvariant());

        // The undeclared paths are requested as browser navigations, so what they get back is the selection
        // page rather than the status a non-navigating caller is refused with — which keeps these
        // assertions about the path list rather than about content negotiation.
        _undeclared = await client.SendAsync(AuthProxyFactory.BrowserNavigation("/dashboard"));
        _undeclaredBody = await _undeclared.Content.ReadAsStringAsync();

        // A sibling under the same parent as the declared leaf: /api/portal/report is anonymous,
        // /api/portal/admin must not be.
        _undeclaredSibling = await client.SendAsync(AuthProxyFactory.BrowserNavigation("/api/portal/admin"));
        _undeclaredSiblingBody = await _undeclaredSibling.Content.ReadAsStringAsync();

        _undeclaredLongerFirstSegment = await client.SendAsync(
            AuthProxyFactory.BrowserNavigation($"{AuthProxyFactory.AnonymousFrontendPath}x/token"));
        _undeclaredLongerFirstSegmentBody = await _undeclaredLongerFirstSegment.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_declared_frontend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredFrontend!.StatusCode);
    [Fact] public void should_forward_below_the_declared_frontend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredFrontendChild!.StatusCode);
    [Fact] public void should_forward_the_declared_backend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredBackend!.StatusCode);
    [Fact] public void should_forward_the_declared_path_in_a_different_casing() => Assert.Equal(HttpStatusCode.BadGateway, _declaredFrontendInDifferentCasing!.StatusCode);
    [Fact] public void should_still_select_provider_for_an_undeclared_path() => Assert.Contains("Select Provider", _undeclaredBody);
    [Fact] public void should_still_select_provider_for_an_undeclared_sibling() => Assert.Contains("Select Provider", _undeclaredSiblingBody);
    [Fact] public void should_still_select_provider_for_a_longer_first_segment() => Assert.Contains("Select Provider", _undeclaredLongerFirstSegmentBody);
}
