// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that a malformed registration fingerprint is rejected.
/// </summary>
public class when_evaluating_a_session_with_a_malformed_registration_fingerprint : a_session_policy
{
    CanonicalSessionVerdict _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        properties.Items[CanonicalSessionRegistrationFingerprint.StateKey] = "not-a-fingerprint";
        _result = Evaluate(CanonicalPrincipal(), properties);
    }

    [Fact] void should_return_malformed_registration_state() => _result.ShouldEqual(CanonicalSessionVerdict.MalformedRegistrationState);
    [Fact] void should_not_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeFalse();
}
