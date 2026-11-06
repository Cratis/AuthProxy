// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsVerifier.given;

public class a_verifier : Specification
{
    protected ClientCredentialsVerifier _verifier;
    protected ConfiguredClientCredentialsService _service;
    protected IHttpClientFactory _factory;
    protected RespondingHttpMessageHandler _handler;
    protected ClientCredentialsVerificationResult _result;
    ServiceProvider _provider;

    protected virtual C.DeploymentProfile Profile => C.DeploymentProfile.Default;
    protected virtual bool SigningConfigured => true;
    protected virtual string VerificationPath => "http://verifier.example/verify";

    void Establish()
    {
        var current = new C.AuthProxy
        {
            Profile = Profile,
            Services = new Dictionary<string, C.Service> { ["client"] = new() { Backend = new() { BaseUrl = "https://backend.example" }, ClientCredentials = new() { VerificationPath = VerificationPath } } }
        };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(current);
        var resolver = new ClientCredentialsServiceResolver(options, Substitute.For<ILogger<ClientCredentialsServiceResolver>>());
        resolver.TryResolveForTokenRequest("client", out _service, out _).ShouldBeTrue();
        _handler = new(HttpStatusCode.OK);
        _factory = _handler.AsFactory();
        var services = new ServiceCollection();
        services.AddSingleton(options);
        services.AddSingleton(_factory);
        services.AddTransient<ClientCredentialsVerifier>();
        _provider = services.BuildServiceProvider();
        _verifier = _provider.GetRequiredService<ClientCredentialsVerifier>();
        if (SigningConfigured) current.Services["signed"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() };
    }

    protected async Task Verify() => _result = await _verifier.VerifyAsync(_service, "spec-client", "spec-secret", CancellationToken.None);

    void Destroy()
    {
        _provider.Dispose();
        _handler.Dispose();
    }
}
