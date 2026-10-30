// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that a legacy session is rejected while the configuration is invalid.
/// </summary>
public class when_evaluating_a_legacy_session_while_the_configuration_is_invalid : a_session_policy
{
    CanonicalSessionVerdict _result;

    void Because()
    {
        UseInvalidAuthentication();
        _result = Evaluate(LegacyPrincipal(), new AuthenticationProperties());
    }

    [Fact] void should_return_configuration_invalid() => _result.ShouldEqual(CanonicalSessionVerdict.ConfigurationInvalid);
    [Fact] void should_not_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeFalse();
}
