// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

/// <summary>
/// A mode written as a name the proxy does not have already refuses to start — the binder throws and nothing
/// comes up. A mode written as a <em>number</em> outside the enum does not: it binds silently to a value that
/// is neither mode, and an operator who asked for a closed deployment would get a fully public one, with no
/// error and no log line to say so. The asymmetry is the hazard, so the number is refused the same way the
/// name is.
/// </summary>
/// <remarks>
/// Asserted through the real registration for the same reason as its sibling — the validator deciding
/// correctly is worth nothing if nothing asks it. Stated from the configuration keys rather than an options
/// object because a number in a mode field is exactly the mistake only the keys can make.
/// </remarks>
public class when_admission_names_a_mode_that_is_not_recognized : an_ingress_configuration
{
    Exception? _exception;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "https://backend.example.com",
        [$"{C.Admission.SectionKey}:Mode"] = "2",
    };

    void Because() => _exception = Record.Exception(
        () => _serviceProvider.GetRequiredService<IOptions<C.AuthProxy>>().Value);

    [Fact] void should_refuse_the_configuration() => _exception.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_setting_that_carries_it() =>
        _exception!.Message.ShouldContain($"{C.Admission.SectionKey}:{nameof(C.Admission.Mode)}");
    [Fact] void should_say_what_it_could_have_been() =>
        _exception!.Message.ShouldContain(nameof(C.AdmissionMode.CapabilityOnly));
}
