// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_a_personal_access_token_is_presented : given_a_credential_dispatching_gate
{
    DefaultHttpContext _patOnly = default!;
    DefaultHttpContext _combined = default!;

    async Task Because()
    {
        _patOnly = Request(PatOnlyPath, "POST", $"Bearer {Pat()}");
        _combined = Request(CombinedPath, "GET", $"Bearer {Pat()}");
        await Middleware.InvokeAsync(_patOnly);
        await Middleware.InvokeAsync(_combined);
    }

    [Fact] void should_forward_both_requests() => Forwarder.ReceivedCalls().Count().ShouldEqual(2);
    [Fact] void should_forward_without_an_identity() => Forwarder.Received(2).Forward(Arg.Any<HttpContext>(), Arg.Any<ResolvedBearerRoute>(), null);
    [Fact] void should_hand_the_credential_on_untouched() => _patOnly.Items[BearerRouteDefaults.PassThroughAuthorizationItemKey].ShouldEqual(true);
    [Fact] void should_not_offer_it_to_oauth_validation() => Validator.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_not_write_a_refusal() => _patOnly.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
