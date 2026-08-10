// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress;

namespace Cratis.AuthProxy.SignIns.for_ClientLocationResolver;

public class when_there_are_no_geo_headers : Specification
{
    ClientLocation _result;

    void Because()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.5");
        context.MarkTrustedProxyPeer(true);

        // Trusted, so the geo headers would have been read had there been any. There are none, and the
        // location stays empty rather than being invented from the address.
        _result = new ClientLocationResolver().Resolve(context);
    }

    [Fact] void should_report_the_connection_address() => _result.IpAddress.ShouldEqual("198.51.100.5");
    [Fact] void should_leave_the_location_empty() => _result.Location.ShouldBeEmpty();
}
