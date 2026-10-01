// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// YARP splits and unquotes header values. Authorization must apply to the selected route, not the raw header
/// or the less restricted service whose host was requested.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_a_service_header_uses_yarp_value_syntax(ServiceRoutingHarness harness)
{
    [Theory]
    [InlineData("\"admin\"")]
    [InlineData("admin,")]
    [InlineData("unknown, admin")]
    public async Task should_require_the_claim_of_the_selected_service(string header)
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        using var request = ServiceRoutingHarness.Request("/api/users", "portal.example.test");
        request.Headers.TryAddWithoutValidation(Headers.ServiceId, header);
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(harness.Admin.ReceivedAnythingFor("/api/users"));
        Assert.False(harness.Portal.ReceivedAnythingFor("/api/users"));
    }

    [Theory]
    [InlineData("\"admin\"")]
    [InlineData("admin,")]
    [InlineData("unknown, admin")]
    public async Task should_forward_a_qualified_caller_to_the_selected_service(string header)
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        using var request = ServiceRoutingHarness.Request("/api/users", "portal.example.test", withAdminClaim: true);
        request.Headers.TryAddWithoutValidation(Headers.ServiceId, header);
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(harness.Admin.ReceivedAnythingFor("/api/users"));
        Assert.False(harness.Portal.ReceivedAnythingFor("/api/users"));
    }
}
