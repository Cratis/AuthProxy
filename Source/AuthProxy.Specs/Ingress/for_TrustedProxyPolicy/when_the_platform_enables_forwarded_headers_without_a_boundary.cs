// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

public class when_the_platform_enables_forwarded_headers_without_a_boundary : a_trusted_proxy_policy
{
    readonly ForwardedHeadersOptions _options = new();
    readonly DefaultHttpContext _context = new();

    void Establish()
    {
        // ConfigureWebDefaults uses these options for ASPNETCORE_FORWARDEDHEADERS_ENABLED=true.
        _options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        _options.KnownProxies.Clear();
        _options.KnownIPNetworks.Clear();
        _context.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.7");
        _context.Request.Scheme = "http";
        _context.Request.Headers["X-Forwarded-For"] = "203.0.113.9";
        _context.Request.Headers["X-Forwarded-Proto"] = "https";
    }

    async Task Because()
    {
        _policy.ApplyTo(_options);
        var middleware = new ForwardedHeadersMiddleware(_ => Task.CompletedTask, NullLoggerFactory.Instance, Options.Create(_options));
        await middleware.Invoke(_context);
    }

    [Fact] void should_keep_the_connection_address() => _context.Connection.RemoteIpAddress.ShouldEqual(IPAddress.Parse("10.0.0.7"));
    [Fact] void should_keep_the_transport_scheme() => _context.Request.Scheme.ShouldEqual("http");
}
