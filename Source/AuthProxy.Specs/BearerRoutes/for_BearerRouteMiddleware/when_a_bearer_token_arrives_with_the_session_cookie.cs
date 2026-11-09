// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_a_bearer_token_arrives_with_the_session_cookie : given_a_credential_dispatching_gate
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_refuse_before_validating_either_credential(bool validBearer)
    {
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(validBearer
                ? BearerTokenValidation.Success(new ClaimsPrincipal(new ClaimsIdentity("external")), "tenant-a")
                : BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "rejected"));
        var services = new ServiceCollection();
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure(options => options.Cookie.Name = ".AuthProxy.Session");
        await using var provider = services.BuildServiceProvider();
        var context = Request(OAuthPath, "GET", $"Bearer {JwtLikeToken}");
        context.RequestServices = provider;
        context.Request.Headers.Cookie = ".AuthProxy.Session=value";

        await Middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
        context.Response.ContentType.ShouldEqual("application/json");
        Challenge(context).ShouldEqual("Bearer error=\"invalid_request\"");
        Body(context).ShouldEqual(ErrorBody("invalid_request"));
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
    }
}
