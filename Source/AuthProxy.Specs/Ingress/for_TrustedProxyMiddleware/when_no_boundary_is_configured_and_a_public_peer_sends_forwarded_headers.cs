// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyMiddleware;

/// <summary>
/// Believing every caller is only noted, and noted once, when a public address uses forwarded headers.
/// </summary>
public class when_no_boundary_is_configured_and_a_public_peer_sends_forwarded_headers : Specification
{
    readonly ITrustedProxyPolicy _policy = Substitute.For<ITrustedProxyPolicy>();
    readonly RecordingLogger<AuthProxy.Ingress.TrustedProxyMiddleware> _logger = new();

    void Establish()
    {
        _policy.IsLegacyAllowAll.Returns(true);
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

    [Fact] void should_warn_once() => _logger.Levels.Count(_ => _ == LogLevel.Warning).ShouldEqual(1);
}
