// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_timeouts_cannot_be_honored : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(
        null,
        new C.AuthProxy
        {
            ActivityTimeout = TimeSpan.Zero,
            Services = new Dictionary<string, C.Service>
            {
                ["Portal"] = new()
                {
                    ActivityTimeout = TimeSpan.FromSeconds(-1),
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/", ActivityTimeout = TimeSpan.FromDays(365) },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/", ActivityTimeout = TimeSpan.FromMinutes(1) },
                },
            },
        });

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_fail_once_per_offending_setting() => _result.Failures.Count().ShouldEqual(3);
    [Fact] void should_name_the_root_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:ActivityTimeout ");
    [Fact] void should_name_the_service_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:Services:Portal:ActivityTimeout ");
    [Fact] void should_name_the_endpoint_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:Services:Portal:Backend:ActivityTimeout ");
}
