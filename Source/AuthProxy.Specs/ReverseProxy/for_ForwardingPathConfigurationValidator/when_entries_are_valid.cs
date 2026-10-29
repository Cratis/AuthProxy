// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathConfigurationValidator;

public class when_entries_are_valid : Specification
{
    [Fact]
    void should_normalize_the_path_and_methods()
    {
        ForwardingPathPolicy.Evaluate(new C.ForwardingPathRule { Path = "/.cratis/commands/", Methods = ["get", "GET", "!#$%&'*+-.^_`|~"] }, out var path, out var methods).ShouldEqual(ForwardingPathEntryRejection.None);
        path.ShouldEqual("/.cratis/commands");
        methods.ShouldEqual(["GET", "GET", "!#$%&'*+-.^_`|~"]);
    }

    [Fact]
    void should_validate_both_lists()
    {
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedPaths = [new() { Path = "/api" }], DeniedPaths = [new() { Path = "/openapi" }] } } };
        new ForwardingPathConfigurationValidator().Validate(null, config).Succeeded.ShouldBeTrue();
    }
}
