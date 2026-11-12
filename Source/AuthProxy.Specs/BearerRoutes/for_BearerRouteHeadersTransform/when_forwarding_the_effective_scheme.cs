// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteHeadersTransform;

public class when_forwarding_the_effective_scheme : Specification
{
    [Theory]
    [InlineData("https", "http")]
    [InlineData("https", "http, https")]
    [InlineData("http", "https")]
    public async Task should_replace_all_client_supplied_values_with_exactly_one_effective_scheme(string effective, string supplied)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = effective;
        http.Request.Headers["X-Forwarded-Proto"] = supplied;
        using var proxy = new HttpRequestMessage(HttpMethod.Get, "https://backend.example.test/api");
        proxy.Headers.TryAddWithoutValidation("X-Forwarded-Proto", [supplied, "client-value"]);
        var context = new RequestTransformContext { HttpContext = http, ProxyRequest = proxy };
        var transform = new BearerRouteHeadersTransform();

        await transform.ApplyAsync(context);

        proxy.Headers.GetValues("X-Forwarded-Proto").Single().ShouldEqual(effective);
        http.Request.Headers["X-Forwarded-Proto"].ToString().ShouldEqual(supplied);
    }
}
