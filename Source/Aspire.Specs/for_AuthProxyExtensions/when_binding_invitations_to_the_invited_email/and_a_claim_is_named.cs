// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_binding_invitations_to_the_invited_email;

/// <summary>
/// Naming the claim is what turns an invite from a bearer token anyone signed in can redeem into one bound to
/// the address it was sent to, so the key and its value are the whole of the binding.
/// <para>
/// The Aspire package cannot reference the proxy it configures, so this string is the only thing joining the
/// two. A rename on either side binds nothing and falls back to the empty default — which reads as
/// enforcement deliberately left off rather than as a broken deployment, and leaves the invite redeemable by
/// any authenticated subject holding it.
/// </para>
/// </summary>
public class and_a_claim_is_named : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithInviteEmailBinding("invited_email");

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_bind_the_invitation_to_the_named_claim() => _environment["Cratis__AuthProxy__Invite__EmailClaim"].ShouldEqual("invited_email");
}
