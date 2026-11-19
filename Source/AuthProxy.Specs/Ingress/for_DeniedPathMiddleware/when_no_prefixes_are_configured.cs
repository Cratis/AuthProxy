// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware;

public class when_no_prefixes_are_configured
{
    [Theory]
    [InlineData(null)]
    [InlineData("/internal")]
    [InlineData("/%invalid")]
    [InlineData("/path\\child")]
    public async Task should_not_inspect_or_restrict_the_request(string? rawTarget)
    {
        var context = new DefaultHttpContext();
        context.Features.Get<IHttpRequestFeature>().RawTarget = rawTarget;
        var next = Substitute.For<RequestDelegate>();
        next(context).Returns(Task.CompletedTask);
        var guard = new DeniedPathMiddleware(next, Options.Create(new C.Ingress()), Substitute.For<ILogger<DeniedPathMiddleware>>());

        await guard.InvokeAsync(context);

        await next.Received(1).Invoke(context);
    }
}
