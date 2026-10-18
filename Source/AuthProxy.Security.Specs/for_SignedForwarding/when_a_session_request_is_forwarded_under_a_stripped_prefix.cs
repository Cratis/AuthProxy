// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// A request from a signed-in caller reaches its service with an assertion the service can verify with the pinned
/// public key, naming the service's own audience and the path the service actually received rather than the one the
/// caller requested.
/// </summary>
/// <param name="harness">The running signing proxy and its origins.</param>
[Collection(SignedForwardingSpecCollection.Name)]
public class when_a_session_request_is_forwarded_under_a_stripped_prefix(SignedForwardingHarness harness) : IAsyncLifetime
{
    const string ForwardedPath = "/api/orders/42";

    readonly string _user = SecurityHarness.UniqueUser("signed-session");
    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;
    ForwardedAssertion? _assertion;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();

        _response = await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Post, $"{SignedForwardingHarness.ReportsPrefix}{ForwardedPath}?page=2", _user));
        _forwarded = harness.Reports.LastRequestTo(ForwardedPath);
        _assertion = ForwardedAssertion.From(_forwarded);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_attach_an_assertion() => Assert.NotNull(_assertion);
    [Fact] public void should_verify_with_the_pinned_public_key() => Assert.True(_assertion!.VerifiesWith(harness.Key.PublicKeyPem));
    [Fact] public void should_name_the_signing_key() => Assert.Equal(SignedForwarding.KeyId, _assertion!.HeaderValue("kid"));
    [Fact] public void should_be_typed_as_a_forwarded_identity() => Assert.Equal("cratis-fwd+jwt", _assertion!.HeaderValue("typ"));
    [Fact] public void should_name_the_issuer() => Assert.Equal(SignedForwarding.Issuer, _assertion!.Claim("iss"));
    [Fact] public void should_be_for_the_service_audience() => Assert.Equal(SignedForwardingHarness.ReportsAudience, _assertion!.Claim("aud"));
    [Fact] public void should_bind_the_method() => Assert.Equal("POST", _assertion!.Claim("htm"));
    [Fact] public void should_bind_the_path_the_service_received() => Assert.Equal(ForwardedPath, _assertion!.Claim("htp"));
    [Fact] public void should_carry_the_caller_as_subject() => Assert.Equal(_forwarded!.Value(Headers.PrincipalId), _assertion!.Claim("sub"));
    [Fact] public void should_carry_the_tenant() => Assert.Equal(SignedForwardingHarness.TenantId, _assertion!.Claim("tid"));
    [Fact] public void should_carry_a_header_digest() => Assert.False(string.IsNullOrEmpty(_assertion!.Claim("fwh")));
}
