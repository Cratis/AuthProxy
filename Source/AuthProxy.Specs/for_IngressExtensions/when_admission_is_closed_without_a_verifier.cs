// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

/// <summary>
/// Closing the door and naming nobody who holds the key is the one misconfiguration that cannot announce
/// itself later: the deployment starts, and then answers every caller alive with the same deliberately
/// silent refusal. Refusing at startup is the only moment it can be said out loud.
/// </summary>
/// <remarks>
/// Asserted through the real registration rather than on the validator alone, because a validator nothing
/// registers is a validator that never runs — which is the same silence in a different place. The validator's
/// own specs prove what it decides; this one proves it is asked at all.
/// </remarks>
public class when_admission_is_closed_without_a_verifier : an_ingress_configuration
{
    Exception? _exception;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "https://backend.example.com",
        [$"{C.Admission.SectionKey}:Mode"] = nameof(C.AdmissionMode.CapabilityOnly),
    };

    void Because() => _exception = Record.Exception(
        () => _serviceProvider.GetRequiredService<IOptions<C.AuthProxy>>().Value);

    [Fact] void should_refuse_the_configuration() => _exception.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_setting_that_clears_it() =>
        _exception!.Message.ShouldContain($"{C.Admission.SectionKey}:Capability:{nameof(C.AdmissionCapability.VerifierUrl)}");
}
