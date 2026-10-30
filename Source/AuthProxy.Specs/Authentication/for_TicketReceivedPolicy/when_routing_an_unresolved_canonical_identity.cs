// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that an unresolved canonical identity fails.
/// </summary>
public class when_routing_an_unresolved_canonical_identity : resolutions
{
    TicketReceivedRoute _result;

    void Because() => _result = TicketReceivedPolicy.Route(Failed(), new AuthenticationProperties());

    [Fact] void should_fail() => _result.ShouldEqual(TicketReceivedRoute.Fail);
}
