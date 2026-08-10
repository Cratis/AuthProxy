// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress;

namespace Cratis.AuthProxy.SignIns.for_ClientLocationResolver.when_resolving_from_forwarded_and_geo_headers;

/// <summary>
/// A request that came through the deployment's own infrastructure has its geo headers believed — and still
/// takes its address from the connection, because that is where the forwarded-headers middleware has already
/// put the trusted answer.
/// </summary>
/// <remarks>
/// The connection address and the raw header deliberately disagree here. Reading the header back would report
/// <c>203.0.113.7</c> while every other part of the proxy — the cookie decisions, the reverse-proxy transform,
/// the access log — used the address the middleware settled on, so the assertion is as much about consistency
/// as about trust.
/// </remarks>
public class and_the_peer_is_trusted : Specification
{
    ClientLocation _result;

    void Because()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.5");
        context.MarkTrustedProxyPeer(true);
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.7, 10.0.0.1";
        context.Request.Headers["X-Geo-City"] = "Oslo";
        context.Request.Headers["X-Geo-Region"] = "Oslo";
        context.Request.Headers["X-Geo-Country"] = "NO";

        _result = new ClientLocationResolver().Resolve(context);
    }

    [Fact] void should_report_the_address_the_middleware_settled_on() => _result.IpAddress.ShouldEqual("198.51.100.5");
    [Fact] void should_not_report_an_address_read_from_a_raw_forwarded_header() => _result.IpAddress.ShouldNotEqual("203.0.113.7");
    [Fact] void should_assemble_the_location_from_geo_headers() => _result.Location.ShouldEqual("Oslo, Oslo, NO");
}
