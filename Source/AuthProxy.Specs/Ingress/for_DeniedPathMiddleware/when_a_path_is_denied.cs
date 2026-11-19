// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware;

public class when_a_path_is_denied
{
    [Theory]
    [InlineData("/internal")]
    [InlineData("/internal/")]
    [InlineData("/internal/child")]
    [InlineData("/INTERNAL/CHILD")]
    [InlineData("/internal//child")]
    [InlineData("//internal")]
    [InlineData("/./internal")]
    [InlineData("/public/../internal")]
    [InlineData("/public/%2e%2E/internal")]
    [InlineData("/%69nternal")]
    [InlineData("/internal?code=do-not-log-this")]
    [InlineData("/internal%2fchild")]
    [InlineData("/%2569nternal")]
    [InlineData("/public%0a")]
    [InlineData(null)]
    public async Task should_answer_an_empty_404_without_running_any_downstream_handler(string? rawTarget)
    {
        var downstreamCalls = 0;
        var logger = Substitute.For<ILogger<DeniedPathMiddleware>>();
        var context = new DefaultHttpContext();
        context.Features.Get<IHttpRequestFeature>().RawTarget = rawTarget;
        context.Request.Path = "/safe-decoded-path";
        context.Request.PathBase = "/different-path-base";
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "authenticated-user")], "test"));
        var guard = new DeniedPathMiddleware(
            _ =>
            {
                downstreamCalls++;
                return Task.CompletedTask;
            },
            Options.Create(new C.Ingress { DeniedPathPrefixes = ["/internal/"] }),
            logger);

        await guard.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
        context.Response.Body.Length.ShouldEqual(0L);
        context.Response.Headers.Count.ShouldEqual(0);
        downstreamCalls.ShouldEqual(0);
        logger.ReceivedCalls().SelectMany(_ => _.GetArguments()).Any(_ => _?.ToString()?.Contains("do-not-log-this", StringComparison.Ordinal) == true).ShouldBeFalse();
    }
}
