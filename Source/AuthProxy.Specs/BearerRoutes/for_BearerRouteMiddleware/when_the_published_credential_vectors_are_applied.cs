// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

/// <summary>
/// Executable mapping of Cratis/Identity's published
/// Source/Identity.Specs/Vectors/arc-mcp-authorization-v1/profiles-and-discovery.json:
/// sessionCookiePresent + authorizationBearerPresent and credentialInUriQuery, on all three profiles,
/// require status 400, JSON, and verifierSelected=false.
/// </summary>
public class when_the_published_credential_vectors_are_applied : given_a_credential_dispatching_gate
{
    [Theory]
    [InlineData(PatOnlyPath, "session", true)]
    [InlineData(OAuthPath, "session", true)]
    [InlineData(CombinedPath, "session", true)]
    [InlineData(PatOnlyPath, "uri", false)]
    [InlineData(OAuthPath, "uri", false)]
    [InlineData(CombinedPath, "uri", false)]
    [InlineData(PatOnlyPath, "uri", true)]
    [InlineData(OAuthPath, "uri", true)]
    [InlineData(CombinedPath, "uri", true)]
    public async Task should_refuse_before_selecting_a_verifier(string path, string presentation, bool header)
    {
        var services = new ServiceCollection();
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure(options => options.Cookie.Name = ".AuthProxy.Session");
        await using var provider = services.BuildServiceProvider();
        var token = path == PatOnlyPath ? Pat() : JwtLikeToken;
        var context = Request(path, "GET", header ? [$"Bearer {token}"] : []);
        context.RequestServices = provider;
        if (presentation == "session") context.Request.Headers.Cookie = ".AuthProxy.Session=fixture";
        else context.Request.QueryString = new QueryString("?access_token=" + JwtLikeToken);

        await Middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
        context.Response.ContentType.ShouldEqual("application/json");
        Body(context).ShouldEqual(ErrorBody("invalid_request"));
        Challenge(context).ShouldEqual("Bearer error=\"invalid_request\"");
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
        context.User.Identity?.IsAuthenticated.ShouldNotEqual(true);
    }
}
