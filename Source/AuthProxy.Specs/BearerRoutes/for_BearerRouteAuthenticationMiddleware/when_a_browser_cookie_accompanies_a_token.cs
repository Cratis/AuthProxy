// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware;

public class when_a_browser_cookie_accompanies_a_token : given.a_real_issued_token_pipeline
{
    [Theory]
    [InlineData("issued")]
    [InlineData("valid-external")]
    [InlineData("invalid-external")]
    public async Task should_refuse_before_any_authentication_or_handoff(string kind)
    {
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>()).Returns(kind == "valid-external"
            ? BearerTokenValidation.Success(new ClaimsPrincipal(new ClaimsIdentity("external")), "tenant-a")
            : BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "invalid external token"));
        var gatePassed = false;
        BetweenGateAndAuthentication = _ => gatePassed = true;
        var context = await Send(cookie: true, token: kind == "issued" ? Token : "eyJhbGciOiJSUzI1NiJ9.e30.c2ln");

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
        context.Response.ContentType.ShouldEqual("application/json");
        context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer error=\"invalid_request\"");
        await context.Response.BodyWriter.FlushAsync(TestContext.Current.CancellationToken);
        context.Response.Body.Position = 0;
        (await new StreamReader(context.Response.Body).ReadToEndAsync(TestContext.Current.CancellationToken)).ShouldEqual(/*lang=json*/ """{"error":"invalid_request"}""");
        context.User.Identity?.IsAuthenticated.ShouldNotEqual(true);
        gatePassed.ShouldBeFalse();
        DownstreamCalls.ShouldEqual(0);
        CookieValidations.ShouldEqual(0);
        JwtAuthentications.ShouldEqual(0);
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
    }
}
