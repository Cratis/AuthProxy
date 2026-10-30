// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that a resolved identity with the exact link marker completes a link.
/// </summary>
public class when_routing_a_resolved_canonical_identity_in_link_mode : resolutions
{
    TicketReceivedRoute _result;

    void Because() => _result = TicketReceivedPolicy.Route(Success(), LinkProperties());

    [Fact] void should_complete_the_link() => _result.ShouldEqual(TicketReceivedRoute.CompleteLink);
}
