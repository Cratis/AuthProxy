// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that protocol assurance is recorded only for a configured provider with a canonical identity contract.
/// </summary>
public class when_deciding_to_record_protocol_assurance : resolutions
{
    readonly C.CanonicalIdentity _contract = new();
    bool _configuredWithContract;
    bool _configuredWithoutContract;
    bool _legacyWithContract;

    void Because()
    {
        _configuredWithContract = TicketReceivedPolicy.RecordsProtocolAssurance(Success(), _contract);
        _configuredWithoutContract = TicketReceivedPolicy.RecordsProtocolAssurance(Success(), null);
        _legacyWithContract = TicketReceivedPolicy.RecordsProtocolAssurance(Legacy(), _contract);
    }

    [Fact] void should_record_when_configured_with_a_contract() => _configuredWithContract.ShouldBeTrue();
    [Fact] void should_not_record_without_a_contract() => _configuredWithoutContract.ShouldBeFalse();
    [Fact] void should_not_record_for_a_legacy_provider() => _legacyWithContract.ShouldBeFalse();
}
