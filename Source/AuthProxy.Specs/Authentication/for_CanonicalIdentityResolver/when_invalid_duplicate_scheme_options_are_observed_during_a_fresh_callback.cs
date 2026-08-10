// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver;

/// <summary>
/// Specifies that a validated-options failure during a fresh callback fails closed instead of becoming legacy authentication.
/// </summary>
public class when_invalid_duplicate_scheme_options_are_observed_during_a_fresh_callback : Specification
{
    CanonicalIdentityResolution _result;

    void Because()
    {
        var options = Substitute.For<IOptionsMonitor<C.Authentication>>();
        options.CurrentValue.Returns(_ => throw new OptionsValidationException(
            C.Authentication.SectionKey,
            typeof(C.Authentication),
            ["Canonical authentication provider schemes must be unique."]));
        var constructor = typeof(CanonicalIdentityResolver).GetConstructor([typeof(IOptionsMonitor<C.Authentication>)]);
        var resolver = (CanonicalIdentityResolver)constructor!.Invoke([options]);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "subject-42")], "microsoft"));

        _result = resolver.Resolve(
            principal,
            "microsoft",
            "https://issuer.example.com/tenant",
            isFreshAuthentication: true);
    }

    [Fact] void should_fail_as_configured_identity_resolution() =>
        (_result.IsConfigured && !_result.Succeeded).ShouldBeTrue();
}
