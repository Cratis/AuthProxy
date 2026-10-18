// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// AuthProxy's own call to a service's identity endpoint carries the caller's identity like a proxied request, so it
/// is signed the same way: a service never has to tell the two apart to know whether to believe them.
/// </summary>
/// <param name="harness">The running signing proxy and its origins.</param>
[Collection(SignedForwardingSpecCollection.Name)]
public class when_identity_details_are_resolved(SignedForwardingHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;
    ForwardedRequest? _identityCall;
    ForwardedAssertion? _assertion;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();

        _response = await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Get, $"{SignedForwardingHarness.ReportsPrefix}/api/me-first", SecurityHarness.UniqueUser("signed-identity")));
        _identityCall = harness.Reports.LastRequestTo(WellKnownPaths.IdentityDetails);
        _assertion = ForwardedAssertion.From(_identityCall);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_call_the_identity_endpoint() => Assert.NotNull(_identityCall);
    [Fact] public void should_attach_an_assertion() => Assert.NotNull(_assertion);
    [Fact] public void should_verify_with_the_pinned_public_key() => Assert.True(_assertion!.VerifiesWith(harness.Key.PublicKeyPem));
    [Fact] public void should_be_for_the_service_audience() => Assert.Equal(SignedForwardingHarness.ReportsAudience, _assertion!.Claim("aud"));
    [Fact] public void should_bind_the_method() => Assert.Equal("GET", _assertion!.Claim("htm"));
    [Fact] public void should_bind_the_identity_endpoint_path() => Assert.Equal(WellKnownPaths.IdentityDetails, _assertion!.Claim("htp"));
    [Fact] public void should_carry_the_caller_as_subject() => Assert.Equal(_identityCall!.Value(Headers.PrincipalId), _assertion!.Claim("sub"));
    [Fact] public void should_carry_the_tenant() => Assert.Equal(SignedForwardingHarness.TenantId, _assertion!.Claim("tid"));
}
