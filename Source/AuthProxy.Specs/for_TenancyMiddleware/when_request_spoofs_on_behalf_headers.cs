// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware;

/// <summary>
/// Only AuthProxy names an actor or presents an on-behalf assertion. Every inbound header in that namespace is removed,
/// including one AuthProxy never writes.
/// </summary>
public class when_request_spoofs_on_behalf_headers : Specification
{
    TenancyMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(new C.AuthProxy());

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>()).Returns(true);

        _middleware = new TenancyMiddleware(
            _ => Task.CompletedTask,
            optionsMonitor,
            tenantResolver,
            Substitute.For<ITenantVerifier>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Headers[Headers.OnBehalfActor] = "spoofed-actor";
        _context.Request.Headers[Headers.OnBehalfAssertion] = "spoofed-assertion";
        _context.Request.Headers["X-Cratis-On-Behalf-Session"] = "spoofed-session";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_strip_the_actor_header() => _context.Request.Headers.ContainsKey(Headers.OnBehalfActor).ShouldBeFalse();
    [Fact] void should_strip_the_assertion_header() => _context.Request.Headers.ContainsKey(Headers.OnBehalfAssertion).ShouldBeFalse();
    [Fact] void should_strip_any_other_header_in_the_namespace() => _context.Request.Headers.ContainsKey("X-Cratis-On-Behalf-Session").ShouldBeFalse();
}
