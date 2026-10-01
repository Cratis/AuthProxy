// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityVerificationConfigurationValidator;

/// <summary>
/// Verification is the default, so a deployment that never mentions it and has no tenant resolution is one
/// that requires verification it can never perform. It is refused at startup like an explicit request is,
/// and the message has to say how to get out of it — an operator upgrading cannot be expected to know the
/// default moved.
/// </summary>
public class when_no_mode_is_stated : Specification
{
    ValidateOptionsResult _withoutTenantResolution;
    ValidateOptionsResult _withoutIdentityResolution;

    void Because()
    {
        var validator = new IdentityVerificationConfigurationValidator();
        var service = new C.Service { Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" } };

        _withoutTenantResolution = validator.Validate(
            name: null,
            new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["main"] = service } });

        _withoutIdentityResolution = validator.Validate(
            name: null,
            new C.AuthProxy
            {
                Services = new Dictionary<string, C.Service>
                {
                    ["main"] = new()
                    {
                        Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
                        ResolveIdentityDetails = false
                    }
                }
            });
    }

    [Fact] void should_refuse_the_deployment() => _withoutTenantResolution.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting_that_clears_it() =>
        _withoutTenantResolution.FailureMessage!.ShouldContain(nameof(C.AuthProxy.TenantResolutions));
    [Fact] void should_name_the_opt_out() =>
        _withoutTenantResolution.FailureMessage!.ShouldContain(nameof(C.IdentityVerificationMode.BestEffort));
    [Fact] void should_name_the_way_to_skip_the_endpoint() =>
        _withoutTenantResolution.FailureMessage!.ShouldContain(nameof(C.Service.ResolveIdentityDetails));
    [Fact] void should_leave_a_service_that_is_never_asked_alone() => _withoutIdentityResolution.Succeeded.ShouldBeTrue();
}
