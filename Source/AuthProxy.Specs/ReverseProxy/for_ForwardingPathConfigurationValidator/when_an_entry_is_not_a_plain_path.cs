// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathConfigurationValidator;

public class when_an_entry_is_not_a_plain_path : Specification
{
    [Theory]
    [InlineData("")]
    [InlineData("api")]
    [InlineData(" /api")]
    [InlineData("/api ")]
    [InlineData("/a//b")]
    [InlineData("/a//")]
    [InlineData("/a/../b")]
    [InlineData("/a/.")]
    [InlineData("/a%2fb")]
    [InlineData("/a?b")]
    [InlineData("/a;b")]
    [InlineData("/a\\b")]
    [InlineData("/a/*")]
    [InlineData("/a/{id}")]
    [InlineData("/a#b")]
    [InlineData("/a:b")]
    [InlineData("/a@b")]
    [InlineData("/café")]
    [InlineData("/a\0b")]
    [InlineData("/a\nb")]
    public void should_name_the_service_list_index_and_reason(string path)
    {
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["reports"] = new() { DeniedPaths = [new() { Path = path }] } } };
        var result = new ForwardingPathConfigurationValidator().Validate(null, config);
        result.Failed.ShouldBeTrue();
        result.Failures.Single().ShouldContain("Service 'reports': DeniedPaths[0]");
        result.Failures.Single().ShouldContain("is refused (");
    }

    [Fact]
    void should_refuse_an_unknown_match_kind() => ForwardingPathPolicy.Evaluate(new C.ForwardingPathRule { Path = "/api", Match = (C.ForwardingPathMatch)99 }, out _, out _).ShouldEqual(ForwardingPathEntryRejection.InvalidMatch);
}
