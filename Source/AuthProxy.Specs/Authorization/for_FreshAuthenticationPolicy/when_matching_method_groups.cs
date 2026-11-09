// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_FreshAuthenticationPolicy;

public class when_matching_method_groups : Specification
{
    [Theory]
    [InlineData("POST", 60)]
    [InlineData("post", 60)]
    [InlineData("PUT", 60)]
    [InlineData("PATCH", 60)]
    [InlineData("DELETE", 60)]
    [InlineData("CONNECT", 60)]
    [InlineData("CUSTOM", 60)]
    [InlineData("GET", 5)]
    [InlineData("HEAD", 10)]
    [InlineData("OPTIONS", 20)]
    [InlineData("TRACE", 30)]
    public void should_use_the_strictest_non_safe_rule_without_borrowing_safe_rules(string method, int seconds)
    {
        var service = new C.Service
        {
            FreshAuthentication =
            [
                new() { Path = "/approve", Methods = ["POST"], MaxAge = TimeSpan.FromSeconds(300) },
                new() { Path = "/approve", Methods = ["DELETE"], MaxAge = TimeSpan.FromSeconds(60) },
                new() { Path = "/approve", Methods = ["GET"], MaxAge = TimeSpan.FromSeconds(5) },
                new() { Path = "/approve", Methods = ["HEAD"], MaxAge = TimeSpan.FromSeconds(10) },
                new() { Path = "/approve", Methods = ["OPTIONS"], MaxAge = TimeSpan.FromSeconds(20) },
                new() { Path = "/approve", Methods = ["TRACE"], MaxAge = TimeSpan.FromSeconds(30) },
            ],
        };
        FreshAuthenticationPolicy.MaxAge(service, "/approve", method).ShouldEqual(TimeSpan.FromSeconds(seconds));
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    [InlineData("TRACE")]
    public void should_not_match_a_get_only_rule_for_another_method(string method)
    {
        var service = new C.Service { FreshAuthentication = [new() { Path = "/approve", Methods = ["GET"] }] };
        FreshAuthenticationPolicy.MaxAge(service, "/approve", method).ShouldBeNull();
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    [InlineData("TRACE")]
    [InlineData("POST")]
    [InlineData("CUSTOM")]
    public void should_match_unscoped_rules_for_every_method(string method)
    {
        var service = new C.Service { FreshAuthentication = [new() { Path = "/approve" }] };
        FreshAuthenticationPolicy.MaxAge(service, "/approve", method).ShouldEqual(TimeSpan.FromMinutes(5));
    }

    [Theory]
    [InlineData("/approve", 300)]
    [InlineData("/approve/detail", 60)]
    [InlineData("/other", null)]
    public void should_only_pool_rules_on_matching_paths(string path, int? seconds)
    {
        var service = new C.Service
        {
            FreshAuthentication =
            [
                new() { Path = "/approve", Prefix = true, Methods = ["POST"], MaxAge = TimeSpan.FromSeconds(300) },
                new() { Path = "/approve/detail", Methods = ["DELETE"], MaxAge = TimeSpan.FromSeconds(60) },
            ],
        };
        TimeSpan? expected = seconds is { } value ? TimeSpan.FromSeconds(value) : null;
        FreshAuthenticationPolicy.MaxAge(service, path, "PUT").ShouldEqual(expected);
    }
}
