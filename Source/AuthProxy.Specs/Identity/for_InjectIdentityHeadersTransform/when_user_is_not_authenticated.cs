// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

public class when_user_is_not_authenticated : Specification
{
    InjectIdentityHeadersTransform _transform;
    RequestTransformContext _transformContext;

    void Establish()
    {
        _transform = new InjectIdentityHeadersTransform();

        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity())
        };

        _transformContext = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/api/test")
        };
        _transformContext.ProxyRequest.Headers.Add(Headers.Principal, "hostile-principal");
        _transformContext.ProxyRequest.Headers.Add(Headers.PrincipalId, "hostile-id");
        _transformContext.ProxyRequest.Headers.Add(Headers.PrincipalName, "hostile-name");
    }

    Task Because() => _transform.ApplyAsync(_transformContext).AsTask();

    [Fact] void should_not_set_identity_headers() =>
        _transformContext.ProxyRequest.Headers.Contains(Headers.Principal).ShouldBeFalse();

    [Fact] void should_remove_the_hostile_principal_id_header() =>
        _transformContext.ProxyRequest.Headers.Contains(Headers.PrincipalId).ShouldBeFalse();

    [Fact] void should_remove_the_hostile_principal_name_header() =>
        _transformContext.ProxyRequest.Headers.Contains(Headers.PrincipalName).ShouldBeFalse();

    [Fact] void should_not_set_tenant_id_header() =>
        _transformContext.ProxyRequest.Headers.Contains(Headers.TenantId).ShouldBeFalse();
}
