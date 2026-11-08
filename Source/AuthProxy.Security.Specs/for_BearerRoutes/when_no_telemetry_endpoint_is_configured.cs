// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Telemetry is off until an endpoint is configured: with no <c language="text">OTEL_*</c> setting the proxy still
/// starts and answers requests.
/// </summary>
public class when_no_telemetry_endpoint_is_configured : IAsyncLifetime
{
    BearerRouteHarness? _harness;
    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        _harness = new BearerRouteHarness();
        using var client = _harness.CreateBearerClient();
        _response = await client.GetAsync($"{BearerRouteHarness.RoutePrefix}/tools", TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        _response?.Dispose();
        if (_harness is not null)
        {
            await _harness.DisposeAsync();
        }
    }

    [Fact] public void should_start_and_answer() => Assert.True((int)_response!.StatusCode < 500);
}
