// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// Arc's default observable query and the legacy alias must select the same authorized destination for both protocols.
/// </summary>
/// <param name="harness">The real proxy and recording origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_query_selectors_route_streams(ServiceRoutingHarness harness)
{
    [Theory]
    [InlineData("?x-cratis-microservice=REPORTS", "reports", null, false)]
    [InlineData("?service=REPORTS", "reports", null, false)]
    [InlineData("?x-cratis-microservice=reports&service=reports", "reports", null, false)]
    [InlineData("?x-cratis-microservice=admin&service=portal", "admin", null, true)]
    [InlineData("?x-cratis-microservice=portal&service=admin", "portal", null, false)]
    [InlineData("?x-cratis-microservice=unknown&service=admin", "admin", null, true)]
    [InlineData("?x-cratis-microservice=reports&service=unknown", "reports", null, false)]
    [InlineData("?x-cratis-microservice=&service=reports", "reports", null, false)]
    [InlineData("?x-cratis-microservice=admin&service=reports", "portal", "portal", false)]
    [InlineData("?x-cratis-microservice=reports&service=portal", "reports", "unknown", false)]
    public async Task should_deliver_websocket_and_sse_payloads_to_the_selected_service(string query, string service, string? header, bool withAdminClaim)
    {
        using var client = harness.CreateSecurityClient();
        var connections = new ObservableConnections(harness);
        using var socketRequest = Request("/api/routing-websocket" + query, header, withAdminClaim);
        await connections.WebSocket(client, socketRequest, service);
        using var eventsRequest = Request("/api/routing-events" + query, header, withAdminClaim);
        await connections.ServerSentEvents(client, eventsRequest, service);
    }

    [Theory]
    [InlineData("?x-cratis-microservice=admin")]
    [InlineData("?service=admin")]
    [InlineData("?x-cratis-microservice=admin&service=portal")]
    [InlineData("?x-cratis-microservice=unknown&service=admin")]
    public async Task should_deny_both_protocols_without_the_selected_services_claim(string query)
    {
        using var client = harness.CreateSecurityClient();
        var connections = new ObservableConnections(harness);
        using var socketRequest = Request("/api/routing-websocket" + query, null, withAdminClaim: false);
        await connections.DeniedWebSocket(client, socketRequest);
        using var eventsRequest = Request("/api/routing-events" + query, null, withAdminClaim: false);
        await connections.DeniedServerSentEvents(client, eventsRequest);
    }

    static HttpRequestMessage Request(string path, string? header, bool withAdminClaim)
    {
        var request = ServiceRoutingHarness.Request(path, withAdminClaim: withAdminClaim);
        if (header is not null)
        {
            request.Headers.TryAddWithoutValidation(Headers.ServiceId, header);
        }
        return request;
    }
}
