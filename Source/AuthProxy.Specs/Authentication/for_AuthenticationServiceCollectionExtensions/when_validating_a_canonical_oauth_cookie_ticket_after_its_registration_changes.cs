// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that OAuth endpoints, claim mappings, and authorization parameters bind a canonical cookie to its issuing registration.
/// </summary>
public class when_validating_a_canonical_oauth_cookie_ticket_after_its_registration_changes : canonical_cookie_registration
{
    readonly Dictionary<string, (bool Accepted, string? SignedOutScheme)> _outcomes = [];

    async Task Because()
    {
        var properties = await IssueCanonicalOAuthTicket();

        UseAuthentication(OAuthAuthentication(
            reverseClaimMappingOrder: true,
            reverseAuthorizationParameterOrder: true));
        _outcomes["unchanged"] = await Validate(CanonicalOAuthPrincipal(), properties);

        UseAuthentication(OAuthAuthentication(subjectJsonField: "login"));
        _outcomes["claim mapping"] = await Validate(CanonicalOAuthPrincipal(), properties);

        UseAuthentication(OAuthAuthentication(authorizationEndpoint: "https://changed.example.com/authorize"));
        _outcomes["authorization endpoint"] = await Validate(CanonicalOAuthPrincipal(), properties);

        UseAuthentication(OAuthAuthentication(tokenEndpoint: "https://changed.example.com/token"));
        _outcomes["token endpoint"] = await Validate(CanonicalOAuthPrincipal(), properties);

        UseAuthentication(OAuthAuthentication(userInformationEndpoint: "https://changed.example.com/user"));
        _outcomes["user-information endpoint"] = await Validate(CanonicalOAuthPrincipal(), properties);

        UseAuthentication(OAuthAuthentication(authorizationParameterValue: "consent"));
        _outcomes["configured authorization parameter"] = await Validate(CanonicalOAuthPrincipal(), properties);

        UseAuthentication(OAuthAuthentication());
        _oauthOptions.AdditionalAuthorizationParameters["prompt"] = "consent";
        _outcomes["effective authorization parameter"] = await Validate(CanonicalOAuthPrincipal(), properties);
    }

    [Fact] void should_accept_unchanged_endpoints_and_reordered_equivalent_collections() => _outcomes["unchanged"].ShouldEqual((true, null));
    [Fact] void should_reject_and_sign_out_after_the_claim_mapping_changes() => _outcomes["claim mapping"].ShouldEqual((false, CookieAuthenticationDefaults.AuthenticationScheme));
    [Fact] void should_reject_and_sign_out_after_the_authorization_endpoint_changes() => _outcomes["authorization endpoint"].ShouldEqual((false, CookieAuthenticationDefaults.AuthenticationScheme));
    [Fact] void should_reject_and_sign_out_after_the_token_endpoint_changes() => _outcomes["token endpoint"].ShouldEqual((false, CookieAuthenticationDefaults.AuthenticationScheme));
    [Fact] void should_reject_and_sign_out_after_the_user_information_endpoint_changes() => _outcomes["user-information endpoint"].ShouldEqual((false, CookieAuthenticationDefaults.AuthenticationScheme));
    [Fact] void should_reject_and_sign_out_after_a_configured_authorization_parameter_changes() => _outcomes["configured authorization parameter"].ShouldEqual((false, CookieAuthenticationDefaults.AuthenticationScheme));
    [Fact] void should_reject_and_sign_out_after_an_effective_authorization_parameter_changes() => _outcomes["effective authorization parameter"].ShouldEqual((false, CookieAuthenticationDefaults.AuthenticationScheme));
}
