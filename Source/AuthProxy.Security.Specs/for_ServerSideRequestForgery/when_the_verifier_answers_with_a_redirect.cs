// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Text.Json;
using Cratis.AuthProxy.Admission;
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
/// OWASP A10 — Server-Side Request Forgery. A verifier that answers a redirect does not get to choose a
/// second address for AuthProxy to POST the caller's capability to.
/// </summary>
/// <remarks>
/// The startup validator constrains the verifier to one absolute http or https URL precisely so a deployment
/// cannot be pointed somewhere it did not mean. A message handler that follows redirects hands that
/// constraint back on the first <c>3xx</c>: an unauthenticated POST to the presentation path becomes an
/// AuthProxy-originated POST to any host the proxy can route to, carrying the caller's plaintext capability
/// in the body — an internal metadata service, an admin API, anything reachable from inside.
/// <para>
/// Asserted against real sockets and the real registration. The redirect is followed, if it is followed at
/// all, inside the primary message handler — below every seam a substitute could stand in at — so nothing
/// short of a client built by the registration under test and a socket it can actually reach would observe
/// this. The sink here is a second endpoint on the same listener, which is the friendliest possible case for
/// a redirect: same scheme, same host, same port.
/// </para>
/// </remarks>
public class when_the_verifier_answers_with_a_redirect : IAsyncLifetime
{
    const string Capability = "admit-secret-capability-value";
    const string Transaction = "3f9c0a1b7e2d4c6f4a2e8d1c0b7a6934";
    const string Challenge = "8b1d5e7a0c3f29417d6b4e2a9c8f0135";

    static readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);

    readonly ConcurrentQueue<string> _sinkReceived = new();

    WebApplication _verifier;
    ServiceProvider _services;
    CapabilityVerification _verification;
    string _baseUrl = string.Empty;

    public async Task InitializeAsync()
    {
        _verifier = await StartRedirectingVerifier();

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "https://backend.example.test",
            [$"{C.Admission.SectionKey}:Mode"] = nameof(C.AdmissionMode.CapabilityOnly),
            [$"{C.Admission.SectionKey}:Capability:VerifierUrl"] = $"{_baseUrl}/admit",
        });
        builder.AddIngressConfiguration();

        _services = builder.Services.BuildServiceProvider();

        _verification = await _services
            .GetRequiredService<ICapabilityVerifier>()
            .Verify(new CapabilityPresentation(Capability, Transaction, Challenge), CancellationToken.None);
    }

    public async Task DisposeAsync()
    {
        await _services.DisposeAsync();
        await _verifier.StopAsync();
        await _verifier.DisposeAsync();
    }

    [Fact]
    public void should_never_post_the_capability_to_the_address_the_verifier_named() =>
        Assert.Empty(_sinkReceived);

    [Fact]
    public void should_refuse_the_presentation() =>
        Assert.False(_verification.IsAdmitted);

    async Task<WebApplication> StartRedirectingVerifier()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        var app = builder.Build();

        // 307 rather than 302, because it is the one that preserves the method and the body — a handler that
        // follows it re-sends the whole presentation, capability included, to the named address.
        app.MapPost("/admit", () => Results.Redirect($"{_baseUrl}/internal-metadata", permanent: false, preserveMethod: true));

        app.MapPost("/internal-metadata", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var body = await reader.ReadToEndAsync();
            _sinkReceived.Enqueue(body);

            // Answers as an admitting verifier would, echoing the presentation back, so that a followed
            // redirect fails both assertions rather than only the one about the sink.
            var presentation = JsonSerializer.Deserialize<CapabilityVerificationRequest>(body, _serializerOptions);

            return Results.Json(new CapabilityVerificationResponse(true, presentation!.Transaction, presentation.Challenge));
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
