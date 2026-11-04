// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

public class when_the_service_does_not_answer_in_time : given.a_sender
{
    sealed class Silent : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, cancellationToken);
            return new HttpResponseMessage();
        }
    }

    protected override HttpMessageHandler CreateHandler() => new Silent();

    protected override TimeSpan Timeout => TimeSpan.FromMilliseconds(50);

    async Task Because() => _delivered = await _sender.Send(CreateRequest(), CancellationToken.None);

    [Fact] void should_give_up_and_report_it_not_delivered() => _delivered.ShouldBeFalse();
}
