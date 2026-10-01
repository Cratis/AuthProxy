// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeout;

public class when_a_web_socket_is_quiet_for_less_than_the_timeout : given.a_streaming_deployment
{
    IReadOnlyList<string> _messages;

    async Task Establish() => await StartWith(TimeSpan.FromSeconds(30));

    async Task Because() => _messages = await ReadWebSocketMessages();

    [Fact] void should_deliver_what_arrived_before_the_silence() => _messages.ShouldContain("first");
    [Fact] void should_keep_the_session_open_until_the_next_message() => _messages.ShouldContain(FinalMessage);
}
