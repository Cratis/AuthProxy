// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that the registration fingerprint is recorded only for a configured provider.
/// </summary>
public class when_deciding_to_record_the_registration_fingerprint : resolutions
{
    bool _configured;
    bool _legacy;

    void Because()
    {
        _configured = TicketReceivedPolicy.RecordsRegistrationFingerprint(Success());
        _legacy = TicketReceivedPolicy.RecordsRegistrationFingerprint(Legacy());
    }

    [Fact] void should_record_for_a_configured_provider() => _configured.ShouldBeTrue();
    [Fact] void should_not_record_for_a_legacy_provider() => _legacy.ShouldBeFalse();
}
