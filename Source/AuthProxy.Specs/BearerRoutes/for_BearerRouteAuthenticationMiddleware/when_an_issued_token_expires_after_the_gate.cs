// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware;

public class when_an_issued_token_expires_after_the_gate : given.a_real_issued_token_pipeline
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task should_refuse_without_switching_to_a_browser(bool cookie, bool patOnly)
    {
        if (patOnly) AcceptPersonalAccessTokensOnly();
        if (cookie)
        {
            var browser = await Send("/browser", cookie: true);
            browser.User.Identity.AuthenticationType.ShouldEqual(CookieAuthenticationDefaults.AuthenticationScheme);
            browser.User.FindFirst(ClientCredentialsDefaults.TenantClaimType).Value.ShouldEqual("tenant-b");
            CookieValidations.ShouldEqual(1);
            CookieValidations = 0;
            DownstreamCalls = 0;
        }

        BetweenGateAndAuthentication = _ => Clock.ExpireAccessToken();
        var context = await Send(cookie: cookie, token: Token);
        context.Response.StatusCode.ShouldEqual(cookie ? StatusCodes.Status400BadRequest : StatusCodes.Status401Unauthorized);
        context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual(cookie
            ? "Bearer error=\"invalid_request\""
            : patOnly ? "Bearer realm=\"direct\"" : $"Bearer error=\"invalid_token\", resource_metadata=\"{Metadata}\"");
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        context.Response.Headers.Location.Count.ShouldEqual(0);
        context.Response.Headers.SetCookie.Count.ShouldEqual(0);
        context.User.Identity?.IsAuthenticated.ShouldNotEqual(true);
        DownstreamCalls.ShouldEqual(0);
        CookieValidations.ShouldEqual(0);
        JwtAuthentications.ShouldEqual(0);
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
    }
}
