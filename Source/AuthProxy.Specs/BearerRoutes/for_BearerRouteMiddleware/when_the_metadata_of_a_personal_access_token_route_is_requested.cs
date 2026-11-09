// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_the_metadata_of_a_personal_access_token_route_is_requested : given_a_credential_dispatching_gate
{
    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("POST")]
    public async Task should_answer_not_found_without_forwarding(string method)
    {
        var context = Request("/.well-known/oauth-protected-resource" + PatOnlyPath, method);
        await Middleware.InvokeAsync(context);

        context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
        Validator.ReceivedCalls().ShouldBeEmpty();
    }

    [Fact]
    public async Task should_still_forward_the_metadata_of_a_route_that_has_some()
    {
        await Middleware.InvokeAsync(Request("/.well-known/oauth-protected-resource" + OAuthPath));
        _ = Forwarder.Received(1).Forward(Arg.Any<HttpContext>(), Arg.Any<ResolvedBearerRoute>(), null);
    }
}
