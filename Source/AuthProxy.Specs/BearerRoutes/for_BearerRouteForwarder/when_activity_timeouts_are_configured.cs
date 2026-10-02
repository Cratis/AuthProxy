// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteForwarder;

public class when_activity_timeouts_are_configured
{
    [Theory]
    [InlineData(null, null, null, 300)]
    [InlineData(900, null, null, 900)]
    [InlineData(900, 600, null, 600)]
    [InlineData(900, 600, 45, 45)]
    public async Task should_apply_backend_then_service_then_root_then_default_precedence(int? root, int? service, int? backend, int expected)
    {
        var timeouts = await CaptureTimeouts(Configuration(root, service, backend));
        timeouts.Single().ShouldEqual(TimeSpan.FromSeconds(expected));
    }

    [Theory]
    [InlineData(900, null, null, 1200, null, null, 1200)]
    [InlineData(900, 600, null, 900, 120, null, 120)]
    [InlineData(900, 600, 45, 900, 600, 1800, 1800)]
    [InlineData(900, 600, 45, 900, 600, null, 600)]
    public async Task should_use_reloaded_configuration_for_the_next_request(int? root, int? service, int? backend, int? nextRoot, int? nextService, int? nextBackend, int expected)
    {
        var timeouts = await CaptureTimeouts(Configuration(root, service, backend), Configuration(nextRoot, nextService, nextBackend));
        timeouts[^1].ShouldEqual(TimeSpan.FromSeconds(expected));
    }

    static async Task<List<TimeSpan?>> CaptureTimeouts(C.AuthProxy initial, C.AuthProxy? reloaded = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddReverseProxy();
        await using var provider = services.BuildServiceProvider();
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(initial);
        var transport = Substitute.For<IHttpForwarder>();
        var timeouts = new List<TimeSpan?>();
        transport.SendAsync(
            Arg.Any<HttpContext>(),
            Arg.Any<string>(),
            Arg.Any<HttpMessageInvoker>(),
            Arg.Any<ForwarderRequestConfig>(),
            Arg.Any<HttpTransformer>()).Returns(call =>
            {
                timeouts.Add(call.Arg<ForwarderRequestConfig>().ActivityTimeout);
                return ValueTask.FromResult(ForwarderError.None);
            });

        using var forwarder = new BearerRouteForwarder(
            transport,
            provider.GetRequiredService<IForwarderHttpClientFactory>(),
            provider.GetRequiredService<ITransformBuilder>(),
            monitor,
            NullLogger<BearerRouteForwarder>.Instance);
        var route = BearerRouteTable.All(initial).Single();
        await forwarder.Forward(new DefaultHttpContext(), route, identity: null);
        if (reloaded is not null)
        {
            monitor.CurrentValue.Returns(reloaded);
            await forwarder.Forward(new DefaultHttpContext(), BearerRouteTable.All(reloaded).Single(), identity: null);
        }

        return timeouts;
    }

    static C.AuthProxy Configuration(int? root, int? service, int? backend) => new()
    {
        ActivityTimeout = Seconds(root),
        Services = new Dictionary<string, C.Service>
        {
            ["app"] = new()
            {
                ActivityTimeout = Seconds(service),
                Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.test/", ActivityTimeout = Seconds(backend) },
                BearerRoutes = [new C.BearerRoute
                {
                    PathPrefix = "/mcp",
                    Issuers = [new C.BearerIssuer { Issuer = "https://issuer.example.test/" }],
                    Audiences = ["api"],
                    AcceptWithoutIdentityVerification = true,
                }],
            },
        },
    };

    static TimeSpan? Seconds(int? value) => value is { } seconds ? TimeSpan.FromSeconds(seconds) : null;
}
