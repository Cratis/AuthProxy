// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A deployment's claim requirements apply to every forwarded request, and a bearer route is no exception: a valid
/// token whose principal does not satisfy them is refused with a bare <c language="text">403</c> and never forwarded.
/// They are checked against the principal the backend would receive — after the route's claim mappings — so a
/// token cannot satisfy a requirement with a raw claim the mapping replaces.
/// </summary>
/// <param name="harness">The running proxy, with claim requirements declared.</param>
[Collection(GatedBearerRouteSpecCollection.Name)]
public class when_the_deployment_requires_claims(GatedBearerRouteHarness harness) : IAsyncLifetime
{
    const string QualifiedPath = $"{BearerRouteHarness.RoutePrefix}/qualified";
    const string WithoutOrganizationPath = $"{BearerRouteHarness.RoutePrefix}/without-organization";
    const string OtherOrganizationPath = $"{BearerRouteHarness.RoutePrefix}/other-organization";
    const string MappedPath = $"{BearerRouteHarness.RoutePrefix}/mapped";
    const string UnmappedPath = $"{BearerRouteHarness.RoutePrefix}/unmapped";

    HttpResponseMessage? _qualified;
    HttpResponseMessage? _withoutOrganization;
    HttpResponseMessage? _otherOrganization;
    HttpResponseMessage? _mapped;
    HttpResponseMessage? _unmapped;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        var organization = new Dictionary<string, object> { [GatedBearerRouteHarness.RequiredClaim] = GatedBearerRouteHarness.RequiredValue };

        _qualified = await Send(client, QualifiedPath, harness.Issuer.Token(organization));
        _withoutOrganization = await Send(client, WithoutOrganizationPath, harness.Issuer.Token());
        _otherOrganization = await Send(client, OtherOrganizationPath, harness.Issuer.Token(new Dictionary<string, object> { [GatedBearerRouteHarness.RequiredClaim] = "Elsewhere" }));

        // The token's own preferred_username is someone else; the route maps it from github_login.
        _mapped = await Send(client, MappedPath, harness.Issuer.Token(new Dictionary<string, object>(organization) { ["preferred_username"] = "someone-else" }));

        // The token's own preferred_username qualifies, but the route replaces it with github_login.
        _unmapped = await Send(client, UnmappedPath, harness.Issuer.Token(new Dictionary<string, object>(organization) { ["github_login"] = "mallory" }));
    }

    public Task DisposeAsync()
    {
        _qualified?.Dispose();
        _withoutOrganization?.Dispose();
        _otherOrganization?.Dispose();
        _mapped?.Dispose();
        _unmapped?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_a_token_satisfying_every_requirement() => Assert.Equal(HttpStatusCode.OK, _qualified!.StatusCode);
    [Fact] public void should_refuse_a_token_without_the_required_claim() => Assert.Equal(HttpStatusCode.Forbidden, _withoutOrganization!.StatusCode);
    [Fact] public void should_refuse_a_token_with_an_unaccepted_value() => Assert.Equal(HttpStatusCode.Forbidden, _otherOrganization!.StatusCode);
    [Fact] public void should_refuse_without_a_challenge() => Assert.Empty(_withoutOrganization!.Headers.WwwAuthenticate);
    [Fact] public void should_not_forward_a_refused_token() => Assert.False(harness.Origin.ReceivedAnythingFor(WithoutOrganizationPath) || harness.Origin.ReceivedAnythingFor(OtherOrganizationPath));
    [Fact] public void should_check_the_service_requirement_after_the_claim_mappings() => Assert.Equal(HttpStatusCode.OK, _mapped!.StatusCode);
    [Fact] public void should_not_let_a_mapped_away_claim_satisfy_the_service_requirement() => Assert.Equal(HttpStatusCode.Forbidden, _unmapped!.StatusCode);

    static Task<HttpResponseMessage> Send(HttpClient client, string path, string token) =>
        client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, token));
}
