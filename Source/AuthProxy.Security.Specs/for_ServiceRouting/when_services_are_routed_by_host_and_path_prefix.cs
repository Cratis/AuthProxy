// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// OWASP A01 — Broken Access Control. Routing by host or path prefix must send each request to the service that
/// claims it, and the service whose authorization requirements were checked must be the service that receives it.
/// A host that reached a service without its requirements applying would be a way around them.
/// </summary>
/// <param name="harness">The running proxy and its three origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_services_are_routed_by_host_and_path_prefix(ServiceRoutingHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _prefixedApi;
    ForwardedRequest? _prefixedAsset;
    bool _portalSawThePrefixedRequest;

    HttpResponseMessage? _adminHostWithoutClaim;
    bool _adminSawTheUnqualifiedCaller;
    HttpResponseMessage? _adminHostWithClaim;
    bool _adminSawTheQualifiedCaller;

    bool _portalSawTheExplicitSelection;
    bool _adminSawTheExplicitSelection;

    HttpResponseMessage? _unrouted;
    HttpResponseMessage? _proxyOwnedPathOnAHost;
    bool _adminSawTheProxyOwnedPath;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.ClearOrigins();
        var prefixed = ServiceRoutingHarness.Request($"{ServiceRoutingHarness.ReportsPrefix}/api/orders?page=2");
        prefixed.Headers.TryAddWithoutValidation(Headers.ServiceId, "portal");
        await client.SendAsync(prefixed);
        _prefixedApi = harness.Reports.LastRequestTo("/api/orders");
        _portalSawThePrefixedRequest = harness.Portal.ReceivedAnythingFor($"{ServiceRoutingHarness.ReportsPrefix}/api/orders")
            || harness.Portal.ReceivedAnythingFor("/api/orders");

        await client.SendAsync(ServiceRoutingHarness.Request($"{ServiceRoutingHarness.ReportsPrefix}/assets/app.js"));
        _prefixedAsset = harness.Reports.LastRequestTo("/assets/app.js");

        harness.ClearOrigins();
        _adminHostWithoutClaim = await client.SendAsync(ServiceRoutingHarness.Request("/api/users", ServiceRoutingHarness.AdminHost));
        _adminSawTheUnqualifiedCaller = harness.Admin.ReceivedAnythingFor("/api/users");

        harness.ClearOrigins();
        _adminHostWithClaim = await client.SendAsync(ServiceRoutingHarness.Request("/api/users", ServiceRoutingHarness.AdminHost, withAdminClaim: true));
        _adminSawTheQualifiedCaller = harness.Admin.ReceivedAnythingFor("/api/users");

        harness.ClearOrigins();
        var explicitSelection = ServiceRoutingHarness.Request("/api/customers", ServiceRoutingHarness.AdminHost);
        explicitSelection.Headers.TryAddWithoutValidation(Headers.ServiceId, "portal");
        await client.SendAsync(explicitSelection);
        _portalSawTheExplicitSelection = harness.Portal.ReceivedAnythingFor("/api/customers");
        _adminSawTheExplicitSelection = harness.Admin.ReceivedAnythingFor("/api/customers");

        harness.ClearOrigins();
        _unrouted = await client.SendAsync(ServiceRoutingHarness.Request("/dashboard"));

        harness.ClearOrigins();
        _proxyOwnedPathOnAHost = await client.SendAsync(ServiceRoutingHarness.Request(WellKnownPaths.Providers, ServiceRoutingHarness.AdminHost, withAdminClaim: true));
        _adminSawTheProxyOwnedPath = harness.Admin.ReceivedAnythingFor(WellKnownPaths.Providers);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_forward_a_prefixed_api_request_to_the_service_claiming_the_prefix() =>
        Assert.NotNull(_prefixedApi);

    [Fact]
    public void should_strip_the_prefix_and_keep_the_query() =>
        Assert.Equal("?page=2", _prefixedApi!.QueryString);

    [Fact]
    public void should_announce_the_stripped_prefix() =>
        Assert.Equal(ServiceRoutingHarness.ReportsPrefix, _prefixedApi!.Value("X-Forwarded-Prefix"));

    [Fact]
    public void should_let_the_prefix_win_over_a_service_header() =>
        Assert.False(_portalSawThePrefixedRequest);

    [Fact]
    public void should_forward_assets_under_the_prefix_to_the_service() =>
        Assert.NotNull(_prefixedAsset);

    [Fact]
    public void should_refuse_a_caller_lacking_the_requirements_of_the_service_the_host_routes_to() =>
        Assert.Equal(HttpStatusCode.Forbidden, _adminHostWithoutClaim!.StatusCode);

    [Fact]
    public void should_not_reach_the_host_routed_service_for_a_refused_caller() =>
        Assert.False(_adminSawTheUnqualifiedCaller);

    [Fact]
    public void should_forward_a_qualified_caller_to_the_service_the_host_routes_to() =>
        Assert.True(_adminSawTheQualifiedCaller);

    [Fact]
    public void should_let_an_explicit_selection_win_over_a_host() =>
        Assert.True(_portalSawTheExplicitSelection);

    [Fact]
    public void should_not_forward_an_explicit_selection_to_the_host_service() =>
        Assert.False(_adminSawTheExplicitSelection);

    [Fact]
    public void should_route_nothing_that_no_service_claims() =>
        Assert.Equal(HttpStatusCode.NotFound, _unrouted!.StatusCode);

    [Fact]
    public void should_answer_proxy_owned_paths_itself_on_a_routed_host() =>
        Assert.Equal(HttpStatusCode.OK, _proxyOwnedPathOnAHost!.StatusCode);

    [Fact]
    public void should_not_forward_proxy_owned_paths_on_a_routed_host() =>
        Assert.False(_adminSawTheProxyOwnedPath);
}
