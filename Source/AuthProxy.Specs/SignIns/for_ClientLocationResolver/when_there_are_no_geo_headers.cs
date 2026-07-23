// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.SignIns.for_ClientLocationResolver;

public class when_there_are_no_geo_headers : Specification
{
    ClientLocation _result;

    void Because()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.5");

        // With no forwarded header the resolver falls back to the connection's remote address.
        _result = new ClientLocationResolver().Resolve(context);
    }

    [Fact] void should_fall_back_to_the_remote_address() => _result.IpAddress.ShouldEqual("198.51.100.5");
    [Fact] void should_leave_the_location_empty() => _result.Location.ShouldBeEmpty();
}
