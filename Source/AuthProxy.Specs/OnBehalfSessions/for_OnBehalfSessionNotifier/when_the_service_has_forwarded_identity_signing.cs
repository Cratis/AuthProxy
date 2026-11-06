// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier;

public class when_the_service_has_forwarded_identity_signing : given.a_session_notifier
{
    void Establish() => _configuration.Value.Services[OnBehalfConfiguration.ServiceName].ForwardedIdentity = new();

    async Task Because() => _acknowledged = await _notifier.Ended(_session, OnBehalfSessionEndReason.GrantExpired, _now, CancellationToken.None);

    [Fact] void should_deliver_the_notification() => _acknowledged.ShouldBeTrue();
    [Fact] void should_send_the_per_call_attestation() => _handler.LastAuthorization!.StartsWith("Bearer ", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_not_send_a_header_envelope() => _handler.LastHeaders.ContainsKey("x-cratis-forwarded-identity-signature").ShouldBeFalse();
}
