// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that registration continuity does not invalidate released legacy cookie tickets.
/// </summary>
public class when_validating_a_legacy_cookie_ticket_without_canonical_claims_or_a_registration_fingerprint : canonical_cookie_registration
{
    bool _result;

    async Task Because()
    {
        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = "released-legacy-provider";
        _result = await IsAccepted(LegacyPrincipal(), properties);
    }

    [Fact] void should_accept_the_ticket() => _result.ShouldBeTrue();
}
