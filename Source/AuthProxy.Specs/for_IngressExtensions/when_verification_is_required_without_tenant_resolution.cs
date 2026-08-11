// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

/// <summary>
/// The default configuration AuthProxy ships with names no tenant resolution, and identity resolution is
/// keyed by tenant — so a deployment that turns verification on and changes nothing else verifies nobody, on
/// every request, while looking entirely healthy. Refusing at startup is what turns "the feature is silently
/// inert" into "the proxy told you which key to set".
/// </summary>
/// <remarks>
/// Asserted through the real registration rather than on the validator alone, because a validator nothing
/// registers is a validator that never runs — which is the same silence in a different place.
/// </remarks>
public class when_verification_is_required_without_tenant_resolution : an_ingress_configuration
{
    Exception? _exception;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "https://backend.example.com",
        [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.Required),
    };

    void Because() => _exception = Record.Exception(
        () => _serviceProvider.GetRequiredService<IOptions<C.AuthProxy>>().Value);

    [Fact] void should_refuse_the_configuration() => _exception.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_setting_that_clears_it() =>
        _exception!.Message.ShouldContain(nameof(C.AuthProxy.TenantResolutions));
    [Fact] void should_say_which_mode_asked_for_it() =>
        _exception!.Message.ShouldContain(nameof(C.IdentityVerificationMode.Required));
}
