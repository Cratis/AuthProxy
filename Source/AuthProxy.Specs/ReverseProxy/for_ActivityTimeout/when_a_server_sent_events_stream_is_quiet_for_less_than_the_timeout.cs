// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeout;

public class when_a_server_sent_events_stream_is_quiet_for_less_than_the_timeout : given.a_streaming_deployment
{
    string _received;

    async Task Establish() => await StartWith(TimeSpan.FromSeconds(30));

    async Task Because() => _received = await ReadServerSentEvents();

    [Fact] void should_deliver_what_arrived_before_the_silence() => _received.ShouldContain("first");
    [Fact] void should_keep_the_stream_open_until_the_next_message() => _received.ShouldContain(FinalMessage);
}
