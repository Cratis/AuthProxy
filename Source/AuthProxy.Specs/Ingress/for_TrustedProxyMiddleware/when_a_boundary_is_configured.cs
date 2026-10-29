// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyMiddleware;

/// <summary>
/// A deployment that names its trusted proxies is never noted.
/// </summary>
public class when_a_boundary_is_configured : Specification
{
    readonly ITrustedProxyPolicy _policy = Substitute.For<ITrustedProxyPolicy>();
    readonly RecordingLogger<AuthProxy.Ingress.TrustedProxyMiddleware> _logger = new();

    void Establish()
    {
        _policy.IsLegacyAllowAll.Returns(false);
    }

    async Task Because()
    {
        var middleware = new AuthProxy.Ingress.TrustedProxyMiddleware(_ => Task.CompletedTask, _policy, _logger);
        await middleware.InvokeAsync(Request("198.51.100.10"));
        await middleware.InvokeAsync(Request("198.51.100.10"));
    }

    static DefaultHttpContext Request(string peer)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.9";
        return context;
    }

    [Fact] void should_not_warn() => _logger.Levels.ShouldNotContain(LogLevel.Warning);
}
