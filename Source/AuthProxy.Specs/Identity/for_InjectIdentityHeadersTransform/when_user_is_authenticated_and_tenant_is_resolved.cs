// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

public class when_user_is_authenticated_and_tenant_is_resolved : Specification
{
    const string TenantId = "22222222-2222-2222-2222-222222222222";

    InjectIdentityHeadersTransform _transform;
    RequestTransformContext _transformContext;

    void Establish()
    {
        _transform = new InjectIdentityHeadersTransform();

        var httpContext = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
        [
            new Claim("oid", "user-42"),
            new Claim("email", "user@example.com")
        ],
        "aad");
        httpContext.User = new ClaimsPrincipal(identity);
        httpContext.Items[TenancyMiddleware.TenantIdItemKey] = TenantId;

        _transformContext = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/api/test")
        };
    }

    Task Because() => _transform.ApplyAsync(_transformContext).AsTask();

    [Fact] void should_set_client_principal_header() =>
        _transformContext.ProxyRequest.Headers.Contains(Headers.Principal).ShouldBeTrue();

    [Fact] void should_set_client_principal_id_header() =>
        _transformContext.ProxyRequest.Headers.GetValues(Headers.PrincipalId).Single().ShouldEqual("user-42");

    [Fact] void should_set_client_principal_name_header() =>
        _transformContext.ProxyRequest.Headers.GetValues(Headers.PrincipalName).Single().ShouldEqual("user@example.com");

    [Fact] void should_set_tenant_id_header() =>
        _transformContext.ProxyRequest.Headers.GetValues(Headers.TenantId).Single().ShouldEqual(TenantId);
}
