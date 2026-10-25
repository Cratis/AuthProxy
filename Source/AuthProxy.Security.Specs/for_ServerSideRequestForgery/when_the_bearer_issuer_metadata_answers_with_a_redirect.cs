// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Security.for_ServerSideRequestForgery;

public class when_the_bearer_issuer_metadata_answers_with_a_redirect : IAsyncLifetime
{
    WebApplication _issuer;
    ServiceProvider _services;
    IReadOnlyCollection<SecurityKey>? _keys;
    int _sinkRequests;

    public async ValueTask InitializeAsync()
    {
        var issuerBuilder = WebApplication.CreateSlimBuilder();
        issuerBuilder.Logging.ClearProviders();
        issuerBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        _issuer = issuerBuilder.Build();
        _issuer.MapGet("/metadata", () => Results.Redirect("/sink"));
        _issuer.MapGet("/sink", () =>
        {
            Interlocked.Increment(ref _sinkRequests);
            return Results.Ok();
        });
        await _issuer.StartAsync();
        var address = _issuer.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single().TrimEnd('/');
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.AddBearerRoutes();
        _services = builder.Services.BuildServiceProvider();
        _keys = await _services.GetRequiredService<IBearerIssuerMetadata>().GetSigningKeys(new ResolvedBearerIssuer("issuer", $"{address}/metadata", [], RequireHttps: false), CancellationToken.None);
    }

    public async ValueTask DisposeAsync()
    {
        await _services.DisposeAsync();
        await _issuer.StopAsync();
        await _issuer.DisposeAsync();
    }

    [Fact] public void should_not_accept_redirected_metadata() => Assert.Null(_keys);
    [Fact] public void should_never_follow_the_redirect() => Assert.Equal(0, _sinkRequests);
}
