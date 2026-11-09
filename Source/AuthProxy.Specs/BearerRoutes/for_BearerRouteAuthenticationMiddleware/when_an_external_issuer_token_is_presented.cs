// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware;

public class when_an_external_issuer_token_is_presented : given.a_real_issued_token_pipeline
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_use_only_the_external_branch_even_with_a_browser_cookie(bool valid)
    {
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>()).Returns(valid
            ? BearerTokenValidation.Success(new ClaimsPrincipal(new ClaimsIdentity("external")), "tenant-a", null)
            : BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "invalid external token"));
        var context = await Send(cookie: true, token: "eyJhbGciOiJSUzI1NiJ9.e30.c2ln");
        context.Response.StatusCode.ShouldEqual(valid ? StatusCodes.Status200OK : StatusCodes.Status401Unauthorized);
        context.Items.ContainsKey(typeof(IssuedBearerRouteCredential)).ShouldBeFalse();
        if (valid) context.User.Identity!.AuthenticationType.ShouldEqual("external");
        else context.User.Identity?.IsAuthenticated.ShouldNotEqual(true);
        await Validator.Received(1).Validate(context.Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
        if (valid) await Forwarder.Received(1).Forward(context, Arg.Any<ResolvedBearerRoute>(), Arg.Any<BearerForwardedIdentity?>());
        else Forwarder.ReceivedCalls().ShouldBeEmpty();
        DownstreamCalls.ShouldEqual(0);
        CookieValidations.ShouldEqual(0);
        JwtAuthentications.ShouldEqual(0);
    }
}
