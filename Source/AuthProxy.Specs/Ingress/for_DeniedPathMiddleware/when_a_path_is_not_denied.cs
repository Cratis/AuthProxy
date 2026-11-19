// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware;

public class when_a_path_is_not_denied
{
    [Theory]
    [InlineData("", "/internally")]
    [InlineData("", "/files/report%2Epdf")]
    [InlineData("", "/public/%2ename")]
    [InlineData("", "/internal-not/x")]
    [InlineData("", "/a/../public/x")]
    [InlineData("", "/a%2f..%2fpublic/x")]
    [InlineData("", "/internalx/child")]
    [InlineData("", "/public/internal")]
    [InlineData("/api", "/internal/x")]
    [InlineData("/shared", "/internal")]
    [InlineData("", "/x/ name")]
    [InlineData("", "/x/a;b")]
    [InlineData("", "/x/%")]
    [InlineData("", "/x/%2Fname")]
    [InlineData("", "/x/%5Cname")]
    [InlineData("", "/x\\child")]
    [InlineData("", "/tenant/.auth/login")]
    [InlineData("", "/.auth/callback")]
    public async Task should_pass_the_original_request_through_unchanged(string pathBase, string path)
    {
        var context = new DefaultHttpContext();
        context.Features.Get<IHttpRequestFeature>().RawTarget = "/unrelated-raw-target?next=/internal";
        context.Request.Path = new PathString(path);
        context.Request.PathBase = pathBase;
        var next = Substitute.For<RequestDelegate>();
        next(context).Returns(Task.CompletedTask);
        var guard = new DeniedPathMiddleware(next, Options.Create(new C.Ingress { DeniedPathPrefixes = ["/internal"] }), Substitute.For<ILogger<DeniedPathMiddleware>>());

        await guard.InvokeAsync(context);

        await next.Received(1).Invoke(context);
        context.Request.Path.Value.ShouldEqual(path);
        context.Request.PathBase.Value.ShouldEqual(pathBase);
        context.Features.Get<IHttpRequestFeature>().RawTarget.ShouldEqual("/unrelated-raw-target?next=/internal");
    }
}
