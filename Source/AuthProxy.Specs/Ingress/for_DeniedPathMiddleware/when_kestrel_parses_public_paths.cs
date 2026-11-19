// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware;

public class when_kestrel_parses_public_paths(given.a_kestrel_host host) : IClassFixture<given.a_kestrel_host>
{
    [Theory]
    [InlineData("/internal//../secret")]
    [InlineData("/internal//%2e%2e/secret")]
    [InlineData("/a/../internal/x")]
    [InlineData("/INTERNAL/x")]
    [InlineData("//internal/x")]
    [InlineData("/internal%2Fx")]
    [InlineData("/internal%2fx")]
    [InlineData("/internal%5Cx")]
    [InlineData("/internal%5cx")]
    [InlineData("/internal\\x")]
    [InlineData("/%69nternal/x")]
    [InlineData("http://localhost/internal/x")]
    public async Task should_refuse_paths_that_could_reach_the_denied_prefix(string target)
    {
        var response = await host.Request(target);

        response.StartsWith("HTTP/1.1 404", StringComparison.Ordinal).ShouldBeTrue();
        response.ShouldNotContain("X-Served-Path:");
    }

    [Theory]
    [InlineData("/internally", "/internally")]
    [InlineData("/x/%20name", "/x/ name")]
    [InlineData("/x/a;b", "/x/a;b")]
    [InlineData("/x/%25", "/x/%")]
    [InlineData("/x/name%2Fchild", "/x/name%2Fchild")]
    [InlineData("/x/name%5Cchild", "/x/name\\child")]
    [InlineData("/x/%252F", "/x/%2F")]
    [InlineData("http://localhost/x/%20name", "/x/ name")]
    public async Task should_serve_unrelated_paths_without_modifying_them(string target, string expectedPath)
    {
        var response = await host.Request(target);

        response.StartsWith("HTTP/1.1 200", StringComparison.Ordinal).ShouldBeTrue();
        response.ShouldContain($"X-Served-Path: {expectedPath}\r\n");
    }

    [Theory]
    [InlineData("/internal/%2e%2e/x")]
    [InlineData("/internal/../x")]
    [InlineData("http://localhost/internal/../x")]
    public async Task should_route_traversal_outside_the_prefix_as_x(string target)
    {
        var response = await host.Request(target);

        response.StartsWith("HTTP/1.1 200", StringComparison.Ordinal).ShouldBeTrue();
        response.ShouldContain("X-Served-Path: /x\r\n");
        response.ShouldContain("X-Routed-X: true\r\n");
    }
}
