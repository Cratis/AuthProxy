// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier;

public class when_the_application_refuses_a_notification : a_session_notifier
{
    protected override HttpStatusCode StatusCode => HttpStatusCode.ServiceUnavailable;

    async Task Because() => _acknowledged = await _notifier.Started(_session, OnBehalfGrant.Live(_now.AddHours(2), Sessions.Represented()), CancellationToken.None);

    [Fact] void should_not_be_acknowledged() => _acknowledged.ShouldBeFalse();
}
