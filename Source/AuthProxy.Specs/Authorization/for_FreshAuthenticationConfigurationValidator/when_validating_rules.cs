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
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["main"] = new() { FreshAuthentication = [new() { Path = "/approve", Methods = ["GET"] }, new() { Path = "/APPROVE/", Methods = ["get"] }] } } };
        new FreshAuthenticationConfigurationValidator().Validate(null, config).Failed.ShouldBeTrue();
    }
}
