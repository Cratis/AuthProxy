// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that failure takes precedence over the link marker.
/// </summary>
public class when_routing_an_unresolved_canonical_identity_in_link_mode : resolutions
{
    TicketReceivedRoute _result;

    void Because() => _result = TicketReceivedPolicy.Route(Failed(), LinkProperties());

    [Fact] void should_fail() => _result.ShouldEqual(TicketReceivedRoute.Fail);
}
