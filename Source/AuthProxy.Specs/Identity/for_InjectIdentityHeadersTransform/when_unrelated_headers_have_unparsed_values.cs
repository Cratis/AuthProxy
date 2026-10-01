// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

public class when_unrelated_headers_have_unparsed_values : Specification
{
    RequestTransformContext _context;

    void Establish()
    {
        _context = new RequestTransformContext
        {
            HttpContext = new DefaultHttpContext(),
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/api/test")
        };
        _context.ProxyRequest.Headers.TryAddWithoutValidation("Accept", "text/plain; q=0.50");
        _context.ProxyRequest.Headers.TryAddWithoutValidation("Cache-Control", "max-age = 60");
        _context.ProxyRequest.Headers.TryAddWithoutValidation("x-ms-client-principal-idp", "forged");
        _context.ProxyRequest.Headers.TryAddWithoutValidation(Headers.TenantId, "forged");
    }

    Task Because() => new InjectIdentityHeadersTransform().ApplyAsync(_context).AsTask();

    [Fact] void should_preserve_the_original_accept_value() => _context.ProxyRequest.Headers.NonValidated["Accept"].Single().ShouldEqual("text/plain; q=0.50");
    [Fact] void should_preserve_the_original_cache_control_value() => _context.ProxyRequest.Headers.NonValidated["Cache-Control"].Single().ShouldEqual("max-age = 60");
    [Fact] void should_still_remove_spoofable_identity_headers() => _context.ProxyRequest.Headers.Contains("x-ms-client-principal-idp").ShouldBeFalse();
    [Fact] void should_still_remove_spoofable_tenant_headers() => _context.ProxyRequest.Headers.Contains(Headers.TenantId).ShouldBeFalse();
}
