// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// End-to-end scenario: verifies that claims declared in <c>ClaimsToForward</c> are extracted
/// from the invite token and included in the <c>x-ms-client-principal</c> header sent to the
/// identity details provider.
/// </summary>
/// <param name="factory">The shared application factory with claims-forwarding config.</param>
public class and_invite_claims_are_forwarded_to_identity_provider(ClaimsForwardingAuthProxyFactory factory)
    : IClassFixture<ClaimsForwardingAuthProxyFactory>, IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim(ClaimsForwardingAuthProxyFactory.FromClaimType, ClaimsForwardingAuthProxyFactory.OrganizationId)
            ]);

        using var client = factory.CreateTestClient(authenticated: true, inviteTokenCookie: token);
        await client.GetAsync("/");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_call_the_identity_details_provider() =>
        Assert.True(factory.IdentityCallCount > 0, "Identity details provider was not called");

    [Fact]
    public void should_forward_mapped_invite_claim_to_identity_provider()
    {
        var capturedClaims = string.Join(", ", factory.CapturedIdentityPrincipal?.Claims?.Select(c => $"{c.Type}={c.Value}") ?? []);
        Assert.True(
            factory.CapturedIdentityPrincipal?.Claims?.Any(c =>
                c.Type == ClaimsForwardingAuthProxyFactory.ToClaimType &&
                c.Value == ClaimsForwardingAuthProxyFactory.OrganizationId),
            $"Expected claim '{ClaimsForwardingAuthProxyFactory.ToClaimType}={ClaimsForwardingAuthProxyFactory.OrganizationId}' in identity request, but captured: [{capturedClaims}]");
    }
}
