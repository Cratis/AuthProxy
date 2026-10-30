// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that a session without canonical state is rejected when its provider is now canonical.
/// </summary>
public class when_evaluating_a_session_recorded_for_a_canonical_provider_without_canonical_state : a_session_policy
{
    CanonicalSessionVerdict _result;

    void Because()
    {
        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = ProviderScheme;
        _result = Evaluate(LegacyPrincipal(), properties);
    }

    [Fact] void should_return_legacy_session_for_canonical_provider() => _result.ShouldEqual(CanonicalSessionVerdict.LegacySessionForCanonicalProvider);
    [Fact] void should_not_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeFalse();
}
