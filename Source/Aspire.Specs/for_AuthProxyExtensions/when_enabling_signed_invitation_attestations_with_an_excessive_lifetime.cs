// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_enabling_signed_invitation_attestations_with_an_excessive_lifetime : an_auth_proxy_resource
{
    Exception? _exception;

    void Because() => _exception = Record.Exception(() => _resource.WithSignedInvitationAttestations(
        "https://lobby.example.com/_invite/stage",
        "https://auth.example.com",
        "ada-lobby",
        "invite-2026-08",
        "private-key",
        TimeSpan.FromSeconds(61)));

    [Fact] void should_reject_the_lifetime() => _exception.ShouldBeOfExactType<ArgumentOutOfRangeException>();
}
