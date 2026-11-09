// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_FreshAuthenticationConfigurationValidator;

public class when_validating_rules : Specification
{
    [Theory]
    [InlineData("/", 300, true)]
    [InlineData("/approve", 1, true)]
    [InlineData("/approve", 86400, true)]
    [InlineData("/approve", 0, false)]
    [InlineData("/approve", -1, false)]
    [InlineData("/approve", 86401, false)]
    [InlineData("relative", 300, false)]
    [InlineData("/a/../b", 300, false)]
    [InlineData("/a%2fb", 300, false)]
    public void should_validate_the_path_and_age(string path, int seconds, bool valid)
    {
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["main"] = new() { FreshAuthentication = [new() { Path = path, MaxAge = TimeSpan.FromSeconds(seconds) }] } } };
        new FreshAuthenticationConfigurationValidator().Validate(null, config).Succeeded.ShouldEqual(valid);
    }

    [Fact]
    public void should_refuse_duplicate_paths_and_methods()
    {
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["main"] = new() { FreshAuthenticationMethodOverrideUnsupported = true, FreshAuthentication = [new() { Path = "/approve", Methods = ["GET"] }, new() { Path = "/APPROVE/", Methods = ["get"] }] } } };
        new FreshAuthenticationConfigurationValidator().Validate(null, config).Failed.ShouldBeTrue();
    }

    [Theory]
    [InlineData("", false, true)]
    [InlineData("", true, true)]
    [InlineData("GET", false, false)]
    [InlineData("HEAD", false, false)]
    [InlineData("DELETE", false, false)]
    [InlineData("CUSTOM", false, false)]
    [InlineData("GET", true, true)]
    [InlineData("DELETE", true, true)]
    public void should_require_attestation_only_for_method_scoped_rules(string method, bool attested, bool valid)
    {
        var service = new C.Service
        {
            FreshAuthenticationMethodOverrideUnsupported = attested,
            FreshAuthentication = [new() { Path = "/approve", Methods = method.Length == 0 ? [] : [method] }],
        };
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["main"] = service } };
        new FreshAuthenticationConfigurationValidator().Validate(null, config).Succeeded.ShouldEqual(valid);
    }

    [Fact]
    public void should_require_the_attestation_on_each_service_and_explain_the_backend_contract()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["first"] = new() { FreshAuthenticationMethodOverrideUnsupported = true, FreshAuthentication = [new() { Path = "/approve", Methods = ["DELETE"] }] },
                ["second"] = new() { FreshAuthentication = [new() { Path = "/read" }, new() { Path = "/approve", Methods = ["GET"] }] },
            },
        };
        var result = new FreshAuthenticationConfigurationValidator().Validate(null, config);
        result.Failed.ShouldBeTrue();
        result.Failures.Single().ShouldEqual("Service 'second' uses method-scoped fresh-authentication rules and must set FreshAuthenticationMethodOverrideUnsupported to true only when the backend does not support method overrides.");
    }
}
