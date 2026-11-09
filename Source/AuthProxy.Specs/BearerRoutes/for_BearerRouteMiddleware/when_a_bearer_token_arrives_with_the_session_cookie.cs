// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

/// <summary>
/// A session cookie beside a bearer token never changes which credential a bearer route consults: the bearer alone
/// is validated, and a refused bearer is not rescued by the cookie.
/// </summary>
public class when_a_bearer_token_arrives_with_the_session_cookie : given_a_credential_dispatching_gate
{
    [Fact]
    public async Task should_refuse_a_rejected_bearer_without_falling_back_to_the_cookie()
    {
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "rejected"));
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure(options => options.Cookie.Name = ".AuthProxy.Session");

        var context = Request(OAuthPath, "GET", $"Bearer {JwtLikeToken}");
        context.RequestServices = services.BuildServiceProvider();
        context.Request.Headers.Cookie = ".AuthProxy.Session=value";

        await Middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
    }
}
