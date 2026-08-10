// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.SignIns.for_ClientLocationResolver.when_resolving_from_forwarded_and_geo_headers;

/// <summary>
/// A caller that is not one of the deployment's own proxies gets none of its claims about itself believed.
/// </summary>
/// <remarks>
/// This spec used to assert the opposite — that the left-most <c>X-Forwarded-For</c> entry won — which made
/// the reported address the one value on the request an attacker most directly controls. Worse, the
/// forwarded-headers middleware consumes entries from the <em>right</em>, so the address recorded against a
/// sign-in was not even the address the rest of the proxy was using for the same request: one request, two
/// different attacker-chosen answers. Neither the address nor the geo headers say anything unless the caller
/// that sent them is trusted, and an unmarked context is not.
/// </remarks>
public class and_the_peer_is_not_trusted : Specification
{
    ClientLocation _result;

    void Because()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.5");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.7, 10.0.0.1";
        context.Request.Headers["X-Geo-City"] = "Oslo";
        context.Request.Headers["X-Geo-Region"] = "Oslo";
        context.Request.Headers["X-Geo-Country"] = "NO";

        _result = new ClientLocationResolver().Resolve(context);
    }

    [Fact] void should_report_the_address_the_request_actually_came_from() => _result.IpAddress.ShouldEqual("198.51.100.5");
    [Fact] void should_not_report_an_address_the_caller_wrote() => _result.IpAddress.ShouldNotEqual("203.0.113.7");
    [Fact] void should_leave_the_location_empty() => _result.Location.ShouldBeEmpty();
}
