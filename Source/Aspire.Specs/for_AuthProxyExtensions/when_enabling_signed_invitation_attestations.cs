// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_enabling_signed_invitation_attestations : an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithSignedInvitationAttestations(
        "https://lobby.example.com/_invite/stage",
        "https://auth.example.com",
        "ada-lobby",
        "invite-2026-08",
        "private-key",
        TimeSpan.FromSeconds(45));

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_emit_the_stage_endpoint() => _environment["Cratis__AuthProxy__Invite__StageUrl"].ShouldEqual("https://lobby.example.com/_invite/stage");
    [Fact] void should_emit_the_issuer() => _environment["Cratis__AuthProxy__Invite__Attestation__Issuer"].ShouldEqual("https://auth.example.com");
    [Fact] void should_emit_the_audience() => _environment["Cratis__AuthProxy__Invite__Attestation__Audience"].ShouldEqual("ada-lobby");
    [Fact] void should_emit_the_active_key() => _environment["Cratis__AuthProxy__Invite__Attestation__ActiveKeyId"].ShouldEqual("invite-2026-08");
    [Fact] void should_emit_the_signing_key_identifier() => _environment["Cratis__AuthProxy__Invite__Attestation__SigningKeys__0__KeyId"].ShouldEqual("invite-2026-08");
    [Fact] void should_emit_the_private_key() => _environment["Cratis__AuthProxy__Invite__Attestation__SigningKeys__0__PrivateKeyPem"].ShouldEqual("private-key");
    [Fact] void should_emit_the_lifetime() => _environment["Cratis__AuthProxy__Invite__Attestation__Lifetime"].ShouldEqual("00:00:45");
}
