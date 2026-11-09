// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

public class when_an_issued_token_is_presented : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    DefaultHttpContext _context = default!;

    async Task Because()
    {
        _context = Request($"{Prefix}/orders", $"Bearer {Issue(IssuedFor)}");
        await Middleware.InvokeAsync(_context);
    }

    [Fact] void should_hand_it_on_to_client_credentials_authentication() => Next.Received(1).Invoke(_context);
    [Fact] void should_carry_the_verified_payload() => ((ClientCredentialsTokenPayload)_context.Items[ClientCredentialsDefaults.ValidatedTokenPayloadItemKey]!).ClientId.ShouldEqual("orders-client");
    [Fact] void should_not_offer_it_to_bearer_validation() => Validator.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_not_forward_it_through_the_bearer_route() => Forwarder.ReceivedCalls().ShouldBeEmpty();
}
