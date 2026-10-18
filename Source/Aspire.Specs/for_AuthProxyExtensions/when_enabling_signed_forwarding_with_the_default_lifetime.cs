// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_enabling_signed_forwarding_with_the_default_lifetime : an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithSignedForwarding("https://auth.example.com", "forwarding-2026-10", "private-key");

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_emit_a_thirty_second_lifetime() => _environment["Cratis__AuthProxy__ForwardingAttestation__Lifetime"].ShouldEqual("00:00:30");
}
