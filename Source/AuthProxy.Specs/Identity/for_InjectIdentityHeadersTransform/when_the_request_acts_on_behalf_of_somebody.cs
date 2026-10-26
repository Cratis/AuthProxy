// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

/// <summary>
/// The represented user is forwarded as the principal, so the application authorizes as them; the actor travels beside
/// it, with the assertion that binds both. Whatever a caller sent in those headers, and any credential of the actor's,
/// never reaches the application.
/// </summary>
public class when_the_request_acts_on_behalf_of_somebody : Specification
{
    const string TenantId = "session-tenant";

    RequestTransformContext _transformContext;
    ClientPrincipal _represented;

    void Establish()
    {
        var httpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "actor"), new Claim("email", "actor@example.com")], "github")),
        };
        httpContext.Items[TenancyMiddleware.TenantIdItemKey] = TenantId;
        _represented = new ClientPrincipal { IdentityProvider = "microsoft", UserId = "represented-user", UserDetails = "user@example.com" };
        httpContext.SetOnBehalf(new OnBehalfContext(
            new OnBehalfSession("session-1", new OnBehalfActor("github", "actor", "actor@example.com"), TenantId, "represented-user", "ISSUE-1", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1)),
            _represented,
            "actor-header",
            "signed-assertion"));

        _transformContext = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/api/test"),
        };
        _transformContext.ProxyRequest.Headers.Add(Headers.OnBehalfActor, "hostile-actor");
        _transformContext.ProxyRequest.Headers.Add(Headers.OnBehalfAssertion, "hostile-assertion");
        _transformContext.ProxyRequest.Headers.Authorization = new("Bearer", "actors-own-token");
    }

    Task Because() => new InjectIdentityHeadersTransform().ApplyAsync(_transformContext).AsTask();

    [Fact] void should_forward_the_represented_user_as_the_principal() => _transformContext.ProxyRequest.Headers.GetValues(Headers.Principal).Single().ShouldEqual(_represented.ToBase64());
    [Fact] void should_forward_the_represented_users_id() => _transformContext.ProxyRequest.Headers.GetValues(Headers.PrincipalId).Single().ShouldEqual("represented-user");
    [Fact] void should_forward_the_actor() => _transformContext.ProxyRequest.Headers.GetValues(Headers.OnBehalfActor).Single().ShouldEqual("actor-header");
    [Fact] void should_forward_the_assertion() => _transformContext.ProxyRequest.Headers.GetValues(Headers.OnBehalfAssertion).Single().ShouldEqual("signed-assertion");
    [Fact] void should_forward_the_sessions_tenant() => _transformContext.ProxyRequest.Headers.GetValues(Headers.TenantId).Single().ShouldEqual(TenantId);
    [Fact] void should_not_forward_any_credential_of_the_actors() => _transformContext.ProxyRequest.Headers.Authorization.ShouldBeNull();
}
