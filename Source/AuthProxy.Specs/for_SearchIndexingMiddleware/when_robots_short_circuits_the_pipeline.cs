// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_robots_short_circuits_the_pipeline : Specification
{
    DefaultHttpContext _context;
    SearchIndexingMiddleware _middleware;
    bool _continued;

    void Establish()
    {
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(new C.AuthProxy { SearchIndexing = new() { Exclude = true } });
        _context = new();
        _context.Request.Method = HttpMethods.Get;
        _context.Request.Path = "/robots.txt";
        _context.Response.Body = new MemoryStream();
        _middleware = new(
            _ =>
            {
                _continued = true;
                return Task.CompletedTask;
            },
            configuration);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_reach_authentication_tenancy_or_the_proxy() => _continued.ShouldBeFalse();
}
