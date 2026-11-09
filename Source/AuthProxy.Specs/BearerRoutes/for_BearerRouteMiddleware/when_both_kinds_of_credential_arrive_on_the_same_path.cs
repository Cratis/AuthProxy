// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_both_kinds_of_credential_arrive_on_the_same_path : given_a_credential_dispatching_gate
{
    const int Rounds = 50;

    DefaultHttpContext[] _personalAccessTokens = default!;
    DefaultHttpContext[] _accessTokens = default!;

    async Task Because()
    {
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(BearerTokenValidation.Success(new ClaimsPrincipal(new ClaimsIdentity("external")), "tenant-a"));
        _personalAccessTokens = [.. Enumerable.Range(0, Rounds).Select(_ => Request(CombinedPath, "GET", $"Bearer {Pat()}"))];
        _accessTokens = [.. Enumerable.Range(0, Rounds).Select(_ => Request(CombinedPath, "GET", $"Bearer {JwtLikeToken}"))];
        await Task.WhenAll(_personalAccessTokens.Concat(_accessTokens).Select(_ => Task.Run(() => Middleware.InvokeAsync(_))));
    }

    [Fact] void should_forward_every_personal_access_token() => Forwarder.Received(Rounds).Forward(Arg.Any<HttpContext>(), Arg.Any<ResolvedBearerRoute>(), null);
    [Fact] void should_forward_every_oauth_token_with_verified_identity() => Forwarder.Received(Rounds).Forward(Arg.Any<HttpContext>(), Arg.Any<ResolvedBearerRoute>(), Arg.Is<BearerForwardedIdentity?>(_ => _ != null));
    [Fact] void should_offer_only_the_access_tokens_to_validation() => Validator.ReceivedCalls().Count().ShouldEqual(Rounds);
    [Fact] void should_not_let_a_personal_access_token_be_refused() => _personalAccessTokens.All(_ => _.Response.StatusCode == StatusCodes.Status200OK).ShouldBeTrue();
    [Fact] void should_admit_every_valid_access_token() => _accessTokens.All(_ => _.Response.StatusCode == StatusCodes.Status200OK && _.User.Identity.AuthenticationType == "external").ShouldBeTrue();
    [Fact] void should_not_mark_an_access_token_as_handed_on() => _accessTokens.Any(_ => _.Items.ContainsKey(BearerRouteDefaults.PassThroughAuthorizationItemKey)).ShouldBeFalse();
}
