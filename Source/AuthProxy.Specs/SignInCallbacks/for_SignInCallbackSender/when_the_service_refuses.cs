// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.SignIns;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_the_service_refuses : given.a_sender
{
    protected override HttpMessageHandler CreateHandler() => _handler = new RecordingHttpMessageHandler(HttpStatusCode.InternalServerError);

    async Task Because() => _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);

    [Fact] void should_report_it_not_delivered() => _delivered.ShouldBeFalse();
}
