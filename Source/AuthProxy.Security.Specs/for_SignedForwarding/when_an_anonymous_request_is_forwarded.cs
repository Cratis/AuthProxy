// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// A request on an anonymous path is signed too, so a service can tell the tenant AuthProxy resolved from one an
/// attacker wrote; it names no subject, because nobody is signed in.
/// </summary>
/// <param name="harness">The running signing proxy and its origins.</param>
[Collection(SignedForwardingSpecCollection.Name)]
public class when_an_anonymous_request_is_forwarded(SignedForwardingHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;
    ForwardedAssertion? _assertion;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();

        _response = await client.SendAsync(SecurityHarness.Anonymous(HttpMethod.Get, SignedForwardingHarness.AnonymousPath));
        _assertion = ForwardedAssertion.From(harness.Reports.LastRequestTo("/public"));
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_attach_an_assertion() => Assert.NotNull(_assertion);
    [Fact] public void should_verify_with_the_pinned_public_key() => Assert.True(_assertion!.VerifiesWith(harness.Key.PublicKeyPem));
    [Fact] public void should_carry_no_subject() => Assert.Null(_assertion!.Claim("sub"));
    [Fact] public void should_carry_the_tenant() => Assert.Equal(SignedForwardingHarness.TenantId, _assertion!.Claim("tid"));
}
