// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackConfigurationValidator;

public class when_validating : Specification
{
    static ValidateOptionsResult Validate(C.Service service) =>
        new SignInCallbackConfigurationValidator().Validate(
            null,
            new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = service } });

    static C.Service ServiceWith(C.SignInCallback? callback) => new()
    {
        Backend = new C.ServiceEndpoint { BaseUrl = "http://app.internal:8080" },
        SignInCallback = callback
    };

    [Fact] void should_accept_a_service_without_a_callback() => Validate(ServiceWith(null)).Succeeded.ShouldBeTrue();
    [Fact] void should_accept_a_valid_callback() => Validate(ServiceWith(new() { Path = "/.cratis/showrunner/sign-in" })).Succeeded.ShouldBeTrue();
    [Fact] void should_default_the_interval_to_twelve_hours() => new C.SignInCallback().Interval.ShouldEqual(TimeSpan.FromHours(12));
    [Fact] void should_default_the_timeout_to_five_seconds() => new C.SignInCallback().Timeout.ShouldEqual(TimeSpan.FromSeconds(5));
    [Fact] void should_reject_a_missing_path() => Validate(ServiceWith(new())).Failed.ShouldBeTrue();
    [Fact] void should_reject_a_relative_path() => Validate(ServiceWith(new() { Path = "sign-in" })).Failed.ShouldBeTrue();
    [Fact] void should_reject_a_path_that_names_a_host() => Validate(ServiceWith(new() { Path = "//evil.example.com/sign-in" })).Failed.ShouldBeTrue();
    [Fact] void should_reject_a_path_with_a_query() => Validate(ServiceWith(new() { Path = "/sign-in?x=1" })).Failed.ShouldBeTrue();
    [Fact] void should_reject_a_non_positive_interval() => Validate(ServiceWith(new() { Path = "/sign-in", Interval = TimeSpan.Zero })).Failed.ShouldBeTrue();
    [Fact] void should_reject_a_non_positive_timeout() => Validate(ServiceWith(new() { Path = "/sign-in", Timeout = TimeSpan.Zero })).Failed.ShouldBeTrue();
    [Fact] void should_reject_an_excessive_timeout() => Validate(ServiceWith(new() { Path = "/sign-in", Timeout = TimeSpan.FromMinutes(5) })).Failed.ShouldBeTrue();
    [Fact] void should_reject_a_secret_that_cannot_be_a_header_value() => Validate(ServiceWith(new() { Path = "/sign-in", Secret = "a\r\nb" })).Failed.ShouldBeTrue();
    [Fact] void should_reject_a_callback_on_a_service_without_a_backend() => Validate(new C.Service { SignInCallback = new() { Path = "/sign-in" } }).Failed.ShouldBeTrue();
}
