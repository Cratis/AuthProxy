// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_a_registration_timeout_is_stated : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(
        null,
        new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Portal"] = new()
                {
                    Registration = new C.ServiceEndpoint { BaseUrl = "https://registration.local/", ActivityTimeout = TimeSpan.FromMinutes(1) },
                },
            },
        });

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_report_one_failure() => _result.Failures.Count().ShouldEqual(1);
    [Fact] void should_name_the_registration_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:Services:Portal:Registration:ActivityTimeout ");
    [Fact] void should_explain_the_supported_endpoints() => _result.FailureMessage!.ShouldContain("ActivityTimeout only applies to Backend and Frontend endpoints, not Registration.");
    [Fact] void should_explain_how_to_correct_the_setting() => _result.FailureMessage!.ShouldContain("Remove this setting.");
}
