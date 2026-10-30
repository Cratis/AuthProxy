// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that a resolved identity without a link marker completes a sign-in.
/// </summary>
public class when_routing_a_resolved_canonical_identity_without_a_link_marker : resolutions
{
    TicketReceivedRoute _result;

    void Because() => _result = TicketReceivedPolicy.Route(Success(), new AuthenticationProperties());

    [Fact] void should_complete_the_sign_in() => _result.ShouldEqual(TicketReceivedRoute.CompleteSignIn);
}
