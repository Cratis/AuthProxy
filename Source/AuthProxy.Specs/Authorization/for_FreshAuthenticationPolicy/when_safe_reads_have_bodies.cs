// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Authorization.for_FreshAuthenticationPolicy;

public class when_safe_reads_have_bodies : Specification
{
    [Theory]
    [InlineData("GET", "/approve", true, true)]
    [InlineData("HEAD", "/approve", true, true)]
    [InlineData("GET", "/approve/child", true, true)]
    [InlineData("GET", "/approve", false, false)]
    [InlineData("POST", "/approve", true, false)]
    [InlineData("GET", "/other", true, false)]
    public void should_use_body_detection_without_reading_a_stream(string method, string path, bool canHaveBody, bool refused)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new BodyDetection(canHaveBody));
        var service = new C.Service { FreshAuthentication = [new() { Path = "/approve", Prefix = true, Methods = ["DELETE"] }] };
        FreshAuthenticationPolicy.RefusesSafeBody(context.Request, service, path).ShouldEqual(refused);
    }

    [Theory]
    [InlineData("GET", 4L, false, true)]
    [InlineData("HEAD", 4L, false, true)]
    [InlineData("GET", 0L, false, false)]
    [InlineData("HEAD", 0L, false, false)]
    [InlineData("GET", null, true, true)]
    [InlineData("HEAD", null, true, true)]
    public void should_also_refuse_body_framing_when_detection_is_unavailable(string method, long? length, bool chunked, bool refused)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.ContentLength = length;
        if (chunked) context.Request.Headers.TransferEncoding = "chunked";
        var service = new C.Service { FreshAuthentication = [new() { Path = "/approve", Methods = ["DELETE"] }] };
        FreshAuthenticationPolicy.RefusesSafeBody(context.Request, service, "/approve").ShouldEqual(refused);
    }

    sealed class BodyDetection(bool canHaveBody) : IHttpRequestBodyDetectionFeature
    {
        public bool CanHaveBody => canHaveBody;
    }
}
