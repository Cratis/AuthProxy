// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

public class when_an_external_token_is_presented : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    DefaultHttpContext _context = default!;

    async Task Because()
    {
        _context = Request($"{Prefix}/orders", $"Bearer {ValidExternalToken}");
        await Middleware.InvokeAsync(_context);
    }

    [Fact] void should_validate_it_as_a_bearer_token() => Validator.ReceivedCalls().Count().ShouldEqual(1);
    [Fact] void should_forward_it_through_the_bearer_route() => Forwarder.Received(1).Forward(_context, Arg.Any<ResolvedBearerRoute>(), Arg.Is<BearerForwardedIdentity?>(_ => _ != null));
    [Fact] void should_not_hand_it_on_to_client_credentials_authentication() => Next.ReceivedCalls().ShouldBeEmpty();
}
