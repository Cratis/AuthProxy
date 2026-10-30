// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a blank registration fingerprint invalidates a canonical session.
/// </summary>
public class when_validating_a_canonical_cookie_ticket_with_a_blank_registration_fingerprint : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        var fingerprint = Fingerprint(properties);
        properties.Items[fingerprint.Key] = " ";
        _result = await Validate(CanonicalPrincipal(), properties);
    }

    [Fact] void should_reject_the_ticket() => _result.Accepted.ShouldBeFalse();
    [Fact] void should_sign_out_the_cookie_scheme() => _result.SignedOutScheme.ShouldEqual(CookieAuthenticationDefaults.AuthenticationScheme);
}
