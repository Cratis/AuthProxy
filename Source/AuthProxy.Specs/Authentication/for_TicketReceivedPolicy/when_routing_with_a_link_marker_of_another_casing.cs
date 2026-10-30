// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that only the exact link marker value completes a link.
/// </summary>
public class when_routing_with_a_link_marker_of_another_casing : resolutions
{
    TicketReceivedRoute _result;

    void Because() => _result = TicketReceivedPolicy.Route(Success(), LinkProperties("True"));

    [Fact] void should_complete_the_sign_in() => _result.ShouldEqual(TicketReceivedRoute.CompleteSignIn);
}
