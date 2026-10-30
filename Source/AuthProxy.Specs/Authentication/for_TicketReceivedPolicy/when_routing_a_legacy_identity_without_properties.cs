// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_TicketReceivedPolicy;

/// <summary>
/// Specifies that a legacy identity without properties completes a sign-in.
/// </summary>
public class when_routing_a_legacy_identity_without_properties : resolutions
{
    TicketReceivedRoute _result;

    void Because() => _result = TicketReceivedPolicy.Route(Legacy(), null);

    [Fact] void should_complete_the_sign_in() => _result.ShouldEqual(TicketReceivedRoute.CompleteSignIn);
}
