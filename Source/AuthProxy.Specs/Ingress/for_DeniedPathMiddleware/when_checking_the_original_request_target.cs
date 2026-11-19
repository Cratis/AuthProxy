// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware;

public class when_checking_the_original_request_target
{
    [Theory]
    [InlineData("", "/internal%2fa/../x", false)]
    [InlineData("", "/a//../internal/x", false)]
    [InlineData("", "/internal%252Fx", false)]
    [InlineData("", "http://localhost/internal%2fa/../x", false)]
    [InlineData("/shared", "/shared/internal%2fa/../x", false)]
    [InlineData("", "/%252e%252e/public", false)]
    [InlineData("", "*", false)]
    [InlineData("", "localhost:443", false)]
    [InlineData("", "http:///internal", false)]
    [InlineData("", "/x/%GG", false)]
    [InlineData("", "/x/%C0%AE", false)]
    [InlineData("", "/a/../public/x", true)]
    [InlineData("", "/files/report%252Epdf", true)]
    [InlineData("", "/a/%252e%252e/public/x", true)]
    [InlineData("/shared", "/shared/public/x", true)]
    [InlineData("", "/public?next=/internal", true)]
    [InlineData("", "/public#fragment/internal", true)]
    [InlineData("", "http://localhost/public?next=/internal", true)]
    [InlineData("", "", true)]
    [InlineData("", null, true)]
    public async Task should_check_the_full_raw_path_without_rewriting_the_request(string pathBase, string? rawTarget, bool allowed)
    {
        var context = new DefaultHttpContext();
        context.Request.PathBase = pathBase;
        context.Request.Path = "/x";
        context.Features.Get<IHttpRequestFeature>().RawTarget = rawTarget;
        context.Response.Body = new MemoryStream();
        var calls = 0;
        var guard = new DeniedPathMiddleware(
            _ =>
            {
                calls++;
                return Task.CompletedTask;
            },
            Options.Create(new C.Ingress { DeniedPathPrefixes = ["/internal", "/shared/internal"] }),
            Substitute.For<ILogger<DeniedPathMiddleware>>());

        await guard.InvokeAsync(context);

        calls.ShouldEqual(allowed ? 1 : 0);
        context.Response.StatusCode.ShouldEqual(allowed ? StatusCodes.Status200OK : StatusCodes.Status404NotFound);
        context.Response.Body.Length.ShouldEqual(0L);
        context.Response.Headers.Count.ShouldEqual(0);
        context.Request.Path.Value.ShouldEqual("/x");
        context.Request.PathBase.Value.ShouldEqual(pathBase);
        context.Features.Get<IHttpRequestFeature>().RawTarget.ShouldEqual(rawTarget);
    }

    [Fact]
    public async Task should_not_prepend_path_base_to_the_already_complete_raw_path()
    {
        var context = new DefaultHttpContext();
        context.Request.PathBase = "/shared";
        context.Request.Path = "/x";
        context.Features.Get<IHttpRequestFeature>().RawTarget = "/shared/internal";
        var next = Substitute.For<RequestDelegate>();
        next(context).Returns(Task.CompletedTask);
        var guard = new DeniedPathMiddleware(next, Options.Create(new C.Ingress { DeniedPathPrefixes = ["/shared/shared/internal"] }), Substitute.For<ILogger<DeniedPathMiddleware>>());

        await guard.InvokeAsync(context);

        await next.Received(1).Invoke(context);
    }
}
