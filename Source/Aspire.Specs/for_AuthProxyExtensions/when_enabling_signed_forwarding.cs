// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_enabling_signed_forwarding : an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithSignedForwarding(
        "https://auth.example.com",
        "forwarding-2026-10",
        "private-key",
        TimeSpan.FromSeconds(20));

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_emit_the_issuer() => _environment["Cratis__AuthProxy__ForwardingAttestation__Issuer"].ShouldEqual("https://auth.example.com");
    [Fact] void should_emit_the_active_key() => _environment["Cratis__AuthProxy__ForwardingAttestation__ActiveKeyId"].ShouldEqual("forwarding-2026-10");
    [Fact] void should_emit_the_signing_key_identifier() => _environment["Cratis__AuthProxy__ForwardingAttestation__SigningKeys__0__KeyId"].ShouldEqual("forwarding-2026-10");
    [Fact] void should_emit_the_private_key() => _environment["Cratis__AuthProxy__ForwardingAttestation__SigningKeys__0__PrivateKeyPem"].ShouldEqual("private-key");
    [Fact] void should_emit_the_lifetime() => _environment["Cratis__AuthProxy__ForwardingAttestation__Lifetime"].ShouldEqual("00:00:20");
}
