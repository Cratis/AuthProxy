// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns.for_ClientLocationResolver;

public class when_resolving_from_forwarded_and_geo_headers : Specification
{
    ClientLocation _result;

    void Because()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.7, 10.0.0.1";
        context.Request.Headers["X-Geo-City"] = "Oslo";
        context.Request.Headers["X-Geo-Region"] = "Oslo";
        context.Request.Headers["X-Geo-Country"] = "NO";

        // The left-most X-Forwarded-For entry is the original client, not the intermediate proxies.
        _result = new ClientLocationResolver().Resolve(context);
    }

    [Fact] void should_use_the_original_client_ip() => _result.IpAddress.ShouldEqual("203.0.113.7");
    [Fact] void should_assemble_the_location_from_geo_headers() => _result.Location.ShouldEqual("Oslo, Oslo, NO");
}
