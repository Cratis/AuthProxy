// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a framework-validated issuer alias does not invalidate an otherwise unchanged OIDC registration.
/// </summary>
public class when_validating_a_canonical_cookie_ticket_with_an_unchanged_registration_and_a_different_validated_issuer : canonical_cookie_registration
{
    bool _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket("https://issuer.example.com/tenant-a");
        _result = await IsAccepted(CanonicalPrincipal("https://issuer.example.com/tenant-b"), properties);
    }

    [Fact] void should_accept_the_ticket() => _result.ShouldBeTrue();
}
