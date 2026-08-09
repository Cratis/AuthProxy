// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that canonical cookie validation fails closed when its opaque registration fingerprint is changed.
/// </summary>
public class when_validating_a_canonical_cookie_ticket_with_a_mismatched_registration_fingerprint : canonical_cookie_registration
{
    bool _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        var fingerprint = Fingerprint(properties);
        properties.Items[fingerprint.Key] = "v1:mismatched";
        _result = await IsAccepted(CanonicalPrincipal(), properties);
    }

    [Fact] void should_reject_the_ticket() => _result.ShouldBeFalse();
}
