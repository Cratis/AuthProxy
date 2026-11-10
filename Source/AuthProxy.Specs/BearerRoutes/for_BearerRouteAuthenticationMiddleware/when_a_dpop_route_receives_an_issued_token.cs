// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteAuthenticationMiddleware;

public class when_a_dpop_route_receives_an_issued_token : given.a_real_issued_token_pipeline
{
    DefaultHttpContext _context;

    void Establish()
    {
        Config.Services["portal"].BearerRoutes[0].Dpop = new() { PublicOrigin = "https://portal.test" };
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "external token required"));
    }

    async Task Because() => _context = await Send(token: Token);

    [Fact] void should_refuse_instead_of_using_the_local_client_credentials_branch() => _context.Response.StatusCode.ShouldEqual(401);
    [Fact] void should_use_external_validation_even_for_a_locally_issued_token() => Validator.Received(1).Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
    [Fact] void should_not_hand_the_request_to_the_client_credentials_handler() => DownstreamCalls.ShouldEqual(0);
}
