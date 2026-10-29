// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>Both streaming transports obey the policy before opening a connection to an origin.</summary>
/// <param name="harness">The running proxy and recording origins.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_streams_use_forwarding_paths(ForwardingPathHarness harness)
{
    [Fact]
    public async Task should_deliver_stream_payloads_after_stripping_the_prefix()
    {
        using var client = harness.CreateSecurityClient();
        var streams = new ForwardingPathStreams(harness);
        await streams.WebSocket(client);
        await streams.ServerSentEvents(client);
    }

    [Fact]
    public async Task should_deliver_stream_payloads_to_a_selected_service()
    {
        using var client = harness.CreateSecurityClient();
        var connections = new ObservableConnections(harness);
        using var socket = ServiceRoutingHarness.Request("/api/routing-websocket?x-cratis-microservice=reports");
        await connections.WebSocket(client, socket, "reports");
        using var events = ServiceRoutingHarness.Request("/api/routing-events?x-cratis-microservice=reports");
        await connections.ServerSentEvents(client, events, "reports");
    }

    [Theory]
    [InlineData("/reports/api/denied-socket")]
    [InlineData("/api/denied-socket?x-cratis-microservice=reports")]
    public async Task should_not_contact_the_origin(string target)
    {
        using var client = harness.CreateSecurityClient();
        var connections = new ObservableConnections(harness);
        using var socket = ServiceRoutingHarness.Request(target);
        await connections.DeniedWebSocket(client, socket, expected: HttpStatusCode.NotFound);
        harness.AssertNoOrigins();
        using var events = ServiceRoutingHarness.Request(target);
        await connections.DeniedServerSentEvents(client, events, expected: HttpStatusCode.NotFound);
        harness.AssertNoOrigins();
    }
}
