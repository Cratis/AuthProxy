// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyMiddleware;

/// <summary>
/// The peer is judged from the address the connection actually came from, and the answer is recorded on the
/// request before anything is allowed to rewrite it.
/// </summary>
/// <remarks>
/// The two contexts are answered by the same policy against the same address, so the only thing that can make
/// them differ is the policy — which is the point. If this middleware were ever moved behind the
/// forwarded-headers middleware, the address it reads would be the one the header claimed and an untrusted
/// caller could mark itself trusted by naming a trusted address.
/// </remarks>
public class when_marking_the_peer : Specification
{
    readonly ITrustedProxyPolicy _policy = Substitute.For<ITrustedProxyPolicy>();
    DefaultHttpContext _trusted;
    DefaultHttpContext _untrusted;

    void Establish()
    {
        _trusted = new DefaultHttpContext();
        _trusted.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.7");
        _untrusted = new DefaultHttpContext();
        _untrusted.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.10");

        _policy.IsTrusted(IPAddress.Parse("10.0.0.7")).Returns(true);
        _policy.IsTrusted(IPAddress.Parse("198.51.100.10")).Returns(false);
    }

    async Task Because()
    {
        var middleware = new AuthProxy.Ingress.TrustedProxyMiddleware(_ => Task.CompletedTask, _policy);
        await middleware.InvokeAsync(_trusted);
        await middleware.InvokeAsync(_untrusted);
    }

    [Fact] void should_mark_a_trusted_peer() => _trusted.IsFromTrustedProxy().ShouldBeTrue();
    [Fact] void should_not_mark_an_untrusted_peer() => _untrusted.IsFromTrustedProxy().ShouldBeFalse();
    [Fact] void should_not_trust_a_request_nobody_marked() => new DefaultHttpContext().IsFromTrustedProxy().ShouldBeFalse();
}
