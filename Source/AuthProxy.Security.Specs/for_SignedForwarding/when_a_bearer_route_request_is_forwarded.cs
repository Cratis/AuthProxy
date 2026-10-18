// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// A request accepted on a bearer route is signed like a session request: the identity the token established and the
/// tenant it names arrive with an assertion the service can verify, and a caller's own assertion does not.
/// </summary>
/// <param name="harness">The running signing proxy, origin and issuer.</param>
[Collection(SignedBearerRouteSpecCollection.Name)]
public class when_a_bearer_route_request_is_forwarded(SignedBearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";
    const string Forged = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.forged";

    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;
    ForwardedAssertion? _assertion;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        var request = BearerRouteHarness.WithToken(HttpMethod.Post, Path, harness.Issuer.Token());
        request.Headers.TryAddWithoutValidation(Headers.ForwardedIdentity, Forged);
        _response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);
        _assertion = ForwardedAssertion.From(_forwarded);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_attach_an_assertion() => Assert.NotNull(_assertion);
    [Fact] public void should_not_forward_the_callers_assertion() => Assert.NotEqual(Forged, _assertion!.Token);
    [Fact] public void should_verify_with_the_pinned_public_key() => Assert.True(_assertion!.VerifiesWith(harness.Key.PublicKeyPem));
    [Fact] public void should_be_for_the_service_audience() => Assert.Equal("app", _assertion!.Claim("aud"));
    [Fact] public void should_bind_the_method() => Assert.Equal("POST", _assertion!.Claim("htm"));
    [Fact] public void should_bind_the_path() => Assert.Equal(Path, _assertion!.Claim("htp"));
    [Fact] public void should_carry_the_forwarded_principal_as_subject() => Assert.Equal(BearerRouteHarness.GitHubId, _assertion!.Claim("sub"));
    [Fact] public void should_carry_the_tenant_from_the_token() => Assert.Equal(BearerRouteHarness.TenantId, _assertion!.Claim("tid"));
}
