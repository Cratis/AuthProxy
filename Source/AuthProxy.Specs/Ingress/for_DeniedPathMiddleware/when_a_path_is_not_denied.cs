// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware;

public class when_a_path_is_not_denied
{
    [Theory]
    [InlineData("/internalx")]
    [InlineData("/internalx/child")]
    [InlineData("/public/internal")]
    [InlineData("/api/internal/x")]
    [InlineData("/shared/internal")]
    [InlineData("/internal/../public")]
    [InlineData("/public?destination=/internal")]
    [InlineData("/tenant/.auth/login")]
    [InlineData("/.auth/callback")]
    [InlineData("/api/items")]
    public async Task should_pass_the_original_request_through_unchanged(string rawTarget)
    {
        var context = new DefaultHttpContext();
        context.Features.Get<IHttpRequestFeature>().RawTarget = rawTarget;
        context.Request.Path = "/original-path";
        context.Request.PathBase = "/original-base";
        var next = Substitute.For<RequestDelegate>();
        next(context).Returns(Task.CompletedTask);
        var guard = new DeniedPathMiddleware(next, Options.Create(new C.Ingress { DeniedPathPrefixes = ["/internal"] }), Substitute.For<ILogger<DeniedPathMiddleware>>());

        await guard.InvokeAsync(context);

        await next.Received(1).Invoke(context);
        context.Request.Path.Value.ShouldEqual("/original-path");
        context.Request.PathBase.Value.ShouldEqual("/original-base");
        context.Features.Get<IHttpRequestFeature>().RawTarget.ShouldEqual(rawTarget);
    }
}
