// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.for_ServerSideRequestForgery;

/// <summary>
/// OWASP A10 — Server-Side Request Forgery. The capability verifier is not the only service this proxy
/// posts caller-supplied values to, and a redirect does not get to choose a second address for any of them.
/// </summary>
/// <remarks>
/// This one is the sharpest of the set: the body is the client identifier and the client secret, in
/// plaintext, and the call is reachable from an entirely anonymous POST to the token endpoint. A handler
/// that follows a <c>307</c> re-sends method and body to the named host — and while
/// <c>SocketsHttpHandler</c> strips <c>Authorization</c> across origins, it strips neither the body nor a
/// custom header, so nothing about the credentials is left behind.
/// <para>
/// Asserted against real sockets and the real registration, for the same reason the capability verifier's
/// twin is: the redirect is followed, if it is followed at all, inside the primary message handler, below
/// every seam a substitute could stand in at. The client under test is registered by
/// <c>AddIngressAuthentication</c> with no handler configuration of its own, so what this pins is that the
/// pipeline's default covers a client that never asked to be covered.
/// </para>
/// </remarks>
public class when_the_client_credentials_verifier_answers_with_a_redirect : IAsyncLifetime
{
    const string ClientId = "a-client-identifier";
    const string ClientSecret = "a-plaintext-client-secret";

    readonly ConcurrentQueue<string> _sinkReceived = new();

    WebApplication _verifier;
    ServiceProvider _services;
    ClientCredentialsVerificationResult _result;
    string _baseUrl = string.Empty;

    public async Task InitializeAsync()
    {
        _verifier = await StartRedirectingVerifier();

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "https://backend.example.test",
        });
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();

        _services = builder.Services.BuildServiceProvider();

        _result = await _services
            .GetRequiredService<ClientCredentialsVerifier>()
            .VerifyAsync(
                new ConfiguredClientCredentialsService("app", "/app", new Uri($"{_baseUrl}/verify")),
                ClientId,
                ClientSecret,
                CancellationToken.None);
    }

    public async Task DisposeAsync()
    {
        await _services.DisposeAsync();
        await _verifier.StopAsync();
        await _verifier.DisposeAsync();
    }

    [Fact]
    public void should_never_post_the_credentials_to_the_address_the_verifier_named() =>
        Assert.Empty(_sinkReceived);

    [Fact]
    public void should_not_report_the_credentials_as_verified() =>
        Assert.NotEqual(ClientCredentialsVerificationStatus.Succeeded, _result.Status);

    async Task<WebApplication> StartRedirectingVerifier()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        var app = builder.Build();

        // 307 rather than 302, because it is the one that preserves the method and the body — a handler that
        // follows it re-sends the whole verification request, client secret included, to the named address.
        app.MapPost("/verify", () => Results.Redirect($"{_baseUrl}/internal-metadata", permanent: false, preserveMethod: true));

        app.MapPost("/internal-metadata", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            _sinkReceived.Enqueue(await reader.ReadToEndAsync());

            // Answers as an accepting verifier would, so that a followed redirect fails both assertions
            // rather than only the one about the sink.
            return Results.Ok();
        });

        await app.StartAsync();

        _baseUrl = app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!
            .Addresses
            .First()
            .TrimEnd('/');

        return app;
    }
}
