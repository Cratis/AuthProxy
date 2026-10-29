// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteForwarder;

public class when_a_forwarding_rule_refuses_a_bearer_route : Specification
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_never_call_the_transport(bool serviceMissing)
    {
        var service = new C.Service
        {
            Backend = new() { BaseUrl = "https://backend.example.test/" },
            DeniedPaths = [new() { Path = "/mcp" }],
            BearerRoutes = [new() { PathPrefix = "/mcp", Issuers = [new() { Issuer = "https://issuer.example.test/" }], Audiences = ["api"], AcceptWithoutIdentityVerification = true }]
        };
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = service } };
        var route = BearerRouteTable.All(config).Single();
        if (serviceMissing) config.Services.Clear();
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddReverseProxy();
        await using var provider = services.BuildServiceProvider();
        var transport = Substitute.For<IHttpForwarder>();
        using var forwarder = new BearerRouteForwarder(transport, provider.GetRequiredService<IForwarderHttpClientFactory>(), provider.GetRequiredService<ITransformBuilder>(), monitor, NullLogger<BearerRouteForwarder>.Instance);
        var context = new DefaultHttpContext();
        context.Request.Path = "/mcp";
        context.Response.Body = new MemoryStream();
        await forwarder.Forward(context, route, null);
        transport.ReceivedCalls().ShouldBeEmpty();
        context.Response.StatusCode.ShouldEqual(404);
        context.Response.Headers.CacheControl.ToString().ShouldEqual(UniformDenial.CacheControl);
        context.Response.Body.Position = 0;
        (await new StreamReader(context.Response.Body).ReadToEndAsync(TestContext.Current.CancellationToken)).ShouldEqual(UniformDenial.Body);
    }
}
