// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityVerificationConfigurationValidator;

/// <summary>
/// The default configuration AuthProxy ships with has no tenant resolution at all, and identity resolution
/// is keyed by tenant — so a single-tenant deployment that turns verification on and changes nothing else
/// resolves no tenant for anybody and verifies nobody. Nothing about that looks wrong from the outside: the
/// proxy starts, callers sign in, requests are forwarded. The one thing that does not happen is the check
/// the operator asked for, and it does not happen for everyone, always.
/// <para>
/// A refusal at startup is the only honest answer. At request time the choice is between refusing every
/// caller of a misconfigured deployment and admitting them, and both are wrong for a mistake that is in the
/// configuration rather than in the request.
/// </para>
/// </summary>
public class when_verification_is_required : Specification
{
    ValidateOptionsResult _withoutTenantResolution;
    ValidateOptionsResult _withTenantResolution;
    ValidateOptionsResult _withoutVerification;

    void Because()
    {
        var validator = new IdentityVerificationConfigurationValidator();

        _withoutTenantResolution = validator.Validate(name: null, Configuration(C.IdentityVerificationMode.Required, resolvesTenants: false));
        _withTenantResolution = validator.Validate(name: null, Configuration(C.IdentityVerificationMode.Required, resolvesTenants: true));
        _withoutVerification = validator.Validate(name: null, Configuration(C.IdentityVerificationMode.BestEffort, resolvesTenants: false));
    }

    [Fact] void should_refuse_a_deployment_that_cannot_resolve_a_tenant() => _withoutTenantResolution.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting_that_clears_it() =>
        _withoutTenantResolution.FailureMessage!.ShouldContain(nameof(C.AuthProxy.TenantResolutions));

    [Fact] void should_accept_it_once_a_tenant_resolution_is_declared() => _withTenantResolution.Succeeded.ShouldBeTrue();
    [Fact] void should_leave_an_enrichment_deployment_alone() => _withoutVerification.Succeeded.ShouldBeTrue();

    static C.AuthProxy Configuration(C.IdentityVerificationMode mode, bool resolvesTenants) => new()
    {
        Services = new Dictionary<string, C.Service>
        {
            ["main"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
                IdentityVerification = mode
            }
        },
        TenantResolutions = resolvesTenants
            ? [new C.TenantResolution { Strategy = C.TenantSourceIdentifierResolverType.Specified }]
            : []
    };
}
