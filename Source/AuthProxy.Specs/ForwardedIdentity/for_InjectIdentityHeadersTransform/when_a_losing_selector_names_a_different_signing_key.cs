// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.ForwardedIdentity.for_InjectIdentityHeadersTransform;

public class when_a_losing_selector_names_a_different_signing_key : Specification
{
    RequestTransformContext _context;
    InjectIdentityHeadersTransform _transform;
    string _proof;
    IForwardedIdentitySigner _signer;

    void Establish()
    {
        var signing = new C.ForwardedIdentitySigning { Audience = "routed-backend", KeyId = "routed-key", SecretBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)42, 32).ToArray()) };
        var configuration = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["portal"] = new() { ForwardedIdentity = signing },
                ["other"] = new() { ForwardedIdentity = new() { Audience = "other-backend", KeyId = "other-key", SecretBase64 = signing.SecretBase64 } }
            }
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(configuration);
        _transform = new();
        _signer = new ForwardedIdentitySigner(monitor, TimeProvider.System, Microsoft.Extensions.Logging.Abstractions.NullLogger<ForwardedIdentitySigner>.Instance);
        _context = new() { HttpContext = new DefaultHttpContext(), ProxyRequest = new(HttpMethod.Get, "https://backend.example/final/path") };
        _context.HttpContext.User = new(new ClaimsIdentity([new Claim("oid", "u"), new Claim("email", "name@example.test")], "aad"));
        _context.HttpContext.Request.Headers[Headers.ServiceId] = "other";
        _context.ProxyRequest.Headers.Add(Headers.ServiceId, "other");
        var route = new RouteModel(
            new RouteConfig
            {
                RouteId = "portal-route",
                ClusterId = "portal-cluster",
                Metadata = new Dictionary<string, string> { [ServiceSelection.RouteMetadataKey] = "portal" },
                Match = new() { Path = "/{**catch-all}" }
            },
            new ClusterState("portal-cluster"),
            HttpTransformer.Default);
        _context.HttpContext.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(route), "proxied"));
    }

    async Task Because()
    {
        await _transform.ApplyAsync(_context);
        await new ForwardedIdentitySigningTargetTransform(ForwardedIdentityFlow.ProxiedRequest).ApplyAsync(_context);
        using var invoker = new HttpMessageInvoker(new ForwardedIdentitySigningHandler(_signer, Microsoft.Extensions.Logging.Abstractions.NullLogger<ForwardedIdentitySigningHandler>.Instance) { InnerHandler = new Transport() });
        using var response = await invoker.SendAsync(_context.ProxyRequest, CancellationToken.None);
        _proof = _context.ProxyRequest.Headers.GetValues(Headers.ForwardedIdentitySignature).Single();
    }

    [Fact] void should_select_the_actual_routes_key() => _proof.StartsWith("v1.routed-key.", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_sign_the_actual_service_marker() => _context.ProxyRequest.Headers.GetValues(Headers.ServiceId).Single().ShouldEqual("portal");

    sealed class Transport : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }
}
