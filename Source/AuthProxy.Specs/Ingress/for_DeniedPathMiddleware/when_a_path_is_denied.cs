// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware;

public class when_a_path_is_denied
{
    [Theory]
    [InlineData("", "/internal")]
    [InlineData("", "/internal/")]
    [InlineData("", "/internal/child")]
    [InlineData("", "/INTERNAL/CHILD")]
    [InlineData("", "/internal//child")]
    [InlineData("", "//internal")]
    [InlineData("", "/internal%2fchild")]
    [InlineData("", "/internal%2Fchild")]
    [InlineData("", "/internal%5Cchild")]
    [InlineData("", "/internal\\child")]
    [InlineData("", "/a%2f../internal/x")]
    [InlineData("", "/a%2F..%2Finternal/x")]
    [InlineData("", "/a/%2e%2e/internal/x")]
    [InlineData("", "/a\\..\\internal\\x")]
    [InlineData("", "/./internal/x")]
    [InlineData("", "/a/b/../../internal/x")]
    [InlineData("", "/internal/../public/x")]
    [InlineData("", "/..")]
    [InlineData("", "/a%2f..%2f..%2fpublic/x")]
    [InlineData("", "/public/%2ename")]
    [InlineData("/a", "/../internal/x")]
    [InlineData("/internal", "/child")]
    [InlineData("/shared", "/internal/child")]
    public async Task should_answer_an_empty_404_without_running_any_downstream_handler(string pathBase, string path)
    {
        var downstreamCalls = 0;
        var logger = Substitute.For<ILogger<DeniedPathMiddleware>>();
        var context = new DefaultHttpContext();
        context.Features.Get<IHttpRequestFeature>().RawTarget = "/unrelated-raw-target";
        context.Request.Path = new PathString(path);
        context.Request.PathBase = pathBase;
        context.Request.QueryString = new QueryString("?code=do-not-log-this");
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "authenticated-user")], "test"));
        var guard = new DeniedPathMiddleware(
            _ =>
            {
                downstreamCalls++;
                return Task.CompletedTask;
            },
            Options.Create(new C.Ingress { DeniedPathPrefixes = ["/internal/", "/shared/internal/"] }),
            logger);

        await guard.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
        context.Response.Body.Length.ShouldEqual(0L);
        context.Response.Headers.Count.ShouldEqual(0);
        downstreamCalls.ShouldEqual(0);
        logger.ReceivedCalls().SelectMany(_ => _.GetArguments()).Any(_ => _?.ToString()?.Contains("do-not-log-this", StringComparison.Ordinal) == true).ShouldBeFalse();
    }
}
