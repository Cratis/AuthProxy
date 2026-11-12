// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.WebSockets;
using System.Text;
using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths;

/// <summary>
/// Generic upgrade forwarding only: <c language="text">/.cratis/ws</c> is not an Arc endpoint. Arc multiplexes queries on
/// <c language="text">/.cratis/queries/ws</c> (see <see cref="when_the_query_websocket_is_upgraded"/>).
/// </summary>
/// <param name="harness">The shared Arc harness.</param>
[Collection(ArcCratisSpecCollection.Name)]
public class when_a_websocket_is_upgraded(ArcCratisHarness harness) : given.an_arc_proxy(harness)
{
    WebSocketState _state;
    string _echo;
    string _originMessage;
    ForwardedRequest _forwarded;

    async Task Because()
    {
        using var socket = new ClientWebSocket();
        socket.Options.SetRequestHeader("Host", SessionCookieHarness.ConsoleHost);
        socket.Options.SetRequestHeader("Cookie", string.Join("; ", Cookies));
        var target = new UriBuilder(Client.BaseAddress) { Scheme = "ws", Path = "/.cratis/ws" }.Uri;
        await socket.ConnectAsync(target, Deadline.Token);
        _state = socket.State;
        await socket.SendAsync(Encoding.UTF8.GetBytes("arc-websocket-payload").AsMemory(), WebSocketMessageType.Text, true, Deadline.Token);
        var buffer = new byte[128];
        var message = await socket.ReceiveAsync(buffer.AsMemory(), Deadline.Token);
        _echo = Encoding.UTF8.GetString(buffer, 0, message.Count);
        _originMessage = await Harness.Arc.SocketMessage.Task.WaitAsync(Deadline.Token);
        _forwarded = Assert.Single(Harness.Arc.Received);
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", Deadline.Token);
    }

    [Fact] void should_upgrade_the_connection() => _state.ShouldEqual(WebSocketState.Open);
    [Fact] void should_deliver_the_message_to_the_origin() => _originMessage.ShouldEqual("arc-websocket-payload");
    [Fact] void should_deliver_the_origins_echo() => _echo.ShouldEqual("arc-websocket-payload");
    [Fact] void should_forward_the_websocket_path() => _forwarded.Path.ShouldEqual("/.cratis/ws");
}
