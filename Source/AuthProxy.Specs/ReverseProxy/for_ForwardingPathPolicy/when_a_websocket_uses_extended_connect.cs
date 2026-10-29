// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_a_websocket_uses_extended_connect : Specification
{
    [Fact]
    void should_apply_get_rules()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "CONNECT";
        context.Request.Path = "/socket";
        var feature = Substitute.For<IHttpExtendedConnectFeature>();
        feature.IsExtendedConnect.Returns(true);
        context.Features.Set(feature);
        var service = new C.Service { DeniedPaths = [new() { Path = "/socket", Methods = ["GET"] }] };
        ForwardingPathPolicy.Evaluate(context.Request, service, context.Request.Path).ShouldEqual(ForwardingPathRefusal.Denied);
    }
}
