// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_the_caller_is_not_navigating;

/// <summary>
/// With no providers configured the middleware challenges nobody and forwards everything, and that must
/// stay true for a caller that is not navigating.
/// <para>
/// This is the boundary of the refusal rule. Refusing here would turn a proxy that authenticates nothing
/// into one that refuses every API call — a deployment-wide outage produced by a change meant to correct a
/// status code. The rule only ever converts a refusal that was already happening.
/// </para>
/// </summary>
public class and_no_providers_are_configured : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy());

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication());

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            proxyConfig,
            authConfig,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ITenantResolver>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/api/orders";
        _context.Request.Headers["Sec-Fetch-Dest"] = "empty";
        _context.Response.Body = new MemoryStream();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_refuse_the_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
