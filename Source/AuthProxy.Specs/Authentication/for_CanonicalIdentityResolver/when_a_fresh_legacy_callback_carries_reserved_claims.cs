// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver;

/// <summary>
/// Specifies that a legacy callback cannot smuggle another provider's canonical tuple into a session.
/// </summary>
public class when_a_fresh_legacy_callback_carries_reserved_claims : a_canonical_identity_resolver
{
    CanonicalIdentityResolution _callbackResult;
    CanonicalIdentityResolution _sessionResult;

    protected override C.AuthProxy CreateConfiguration()
    {
        var configuration = base.CreateConfiguration();
        configuration.Authentication.OAuthProviders.Add(new C.OAuthProvider { Name = "Legacy" });
        return configuration;
    }

    void Because()
    {
        _callbackResult = _resolver.Resolve(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("legacy-id", "legacy-subject"),
                new Claim(CanonicalIdentityClaims.ProviderKey, ProviderKey),
                new Claim(CanonicalIdentityClaims.Issuer, Issuer),
                new Claim(CanonicalIdentityClaims.Subject, "canonical-subject")
            ],
            "legacy")),
            "legacy",
            isFreshAuthentication: true);
        _sessionResult = _resolver.Resolve(
            _callbackResult.Principal,
            CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [Fact] void should_remain_a_successful_legacy_resolution() => (_callbackResult.Succeeded && !_callbackResult.IsConfigured).ShouldBeTrue();
    [Fact] void should_strip_every_reserved_claim_before_cookie_storage() => _callbackResult.Principal!.Claims.Any(_ => _.Type.StartsWith("urn:cratis:identity:", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    [Fact] void should_not_validate_the_cookie_principal_as_the_canonical_provider() => _sessionResult.IsConfigured.ShouldBeFalse();
    [Fact] void should_not_create_a_canonical_identity_from_the_spoofed_tuple() => _sessionResult.Identity.ShouldBeNull();
}
