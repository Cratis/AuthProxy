// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that canonical cookie validation fails closed when the registration fingerprint is missing.
/// </summary>
public class when_validating_a_canonical_cookie_ticket_without_a_registration_fingerprint : canonical_cookie_registration
{
    bool _result;

    async Task Because()
    {
        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = ProviderScheme;
        _result = await IsAccepted(CanonicalPrincipal(), properties);
    }

    [Fact] void should_reject_the_ticket() => _result.ShouldBeFalse();
}
