// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that a canonical session is rejected as unresolved while the configuration is invalid, because the resolver fails closed first.
/// </summary>
public class when_evaluating_a_canonical_session_while_the_configuration_is_invalid : a_session_policy
{
    CanonicalSessionVerdict _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        UseInvalidAuthentication();
        _result = Evaluate(CanonicalPrincipal(), properties);
    }

    [Fact] void should_return_unresolved_identity() => _result.ShouldEqual(CanonicalSessionVerdict.UnresolvedIdentity);
    [Fact] void should_not_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeFalse();
}
