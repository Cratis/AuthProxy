// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_lobby_timeouts_are_stated : Specification
{
    C.AuthProxy _options;
    ValidateOptionsResult _result;

    void Establish()
    {
        var prefix = $"{C.AuthProxy.SectionKey}:Invite:Lobby";
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{prefix}:ActivityTimeout"] = "00:01:00",
            [$"{prefix}:Backend:ActivityTimeout"] = "00:02:00",
            [$"{prefix}:Frontend:ActivityTimeout"] = "00:03:00",
            [$"{prefix}:Registration:ActivityTimeout"] = "00:04:00",
        }).Build();
        _options = configuration.GetSection(C.AuthProxy.SectionKey).Get<C.AuthProxy>()!;
    }

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(null, _options);

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_report_one_failure_per_setting() => _result.Failures.Count().ShouldEqual(4);
    [Fact] void should_name_the_lobby_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:Invite:Lobby:ActivityTimeout is not supported.");
    [Fact] void should_name_the_backend_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:Invite:Lobby:Backend:ActivityTimeout is not supported.");
    [Fact] void should_name_the_frontend_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:Invite:Lobby:Frontend:ActivityTimeout is not supported.");
    [Fact] void should_name_the_registration_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:Invite:Lobby:Registration:ActivityTimeout is not supported.");
    [Fact] void should_explain_why_the_settings_are_unsupported() => _result.Failures.All(failure => failure.Contains("Invite:Lobby does not create proxy clusters, so ActivityTimeout cannot apply.", StringComparison.Ordinal)).ShouldBeTrue();
    [Fact] void should_explain_how_to_correct_the_settings() => _result.Failures.All(failure => failure.Contains("Remove this setting and configure the proxied service under Services instead.", StringComparison.Ordinal)).ShouldBeTrue();
}
