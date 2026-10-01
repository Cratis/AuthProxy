// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// A punycode declaration must match the Unicode host ASP.NET exposes from the wire-format Host header.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_a_punycode_host_is_requested(ServiceRoutingHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        using var request = ServiceRoutingHarness.Request("/api/books", "xn--bcher-kva.example.test");
        _response = await client.SendAsync(request);
        _forwarded = harness.Portal.LastRequestTo("/api/books");
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_match_the_host_route() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_forward_to_the_declaring_service() => Assert.NotNull(_forwarded);
    [Fact] public void should_forward_the_selected_service_identifier() => Assert.Equal("portal", _forwarded!.Value(Headers.ServiceId));
}
