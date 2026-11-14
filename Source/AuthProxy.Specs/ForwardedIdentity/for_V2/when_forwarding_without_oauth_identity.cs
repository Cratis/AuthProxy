// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute.Core;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_forwarding_without_oauth_identity : Specification
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_leave_pat_and_metadata_forwards_unwrapped_and_scrub_caller_evidence(bool pat)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddReverseProxy();
        await using var provider = services.BuildServiceProvider();
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example.test/" },
                    ForwardedIdentity = new() { Version = "v2" },
                    BearerRoutes = [new() { PathPrefix = "/api", Issuers = [new() { Issuer = "https://realm.example.test" }], Audiences = ["backend"] }]
                }
            }
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        var transport = Substitute.For<IHttpForwarder>();
        var inspected = false;
        Observe(transport, async call =>
        {
            using var request = new HttpRequestMessage();
            await call.Arg<HttpTransformer>().TransformRequestAsync(call.Arg<HttpContext>(), request, call.Arg<string>(), TestContext.Current.CancellationToken);
            Assert.False(request.Options.TryGetValue(ForwardedIdentitySigningTarget.OptionsKey, out _));
            Assert.False(request.Options.TryGetValue(ForwardedIdentityTrustedContext.OptionsKey, out _));
            Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
            Assert.False(request.Headers.Contains("x-cratis-credential-kind"));
            if (pat) Assert.Equal("Bearer test_pat_opaque", request.Headers.GetValues("Authorization").Single());
            else Assert.False(request.Headers.Contains("Authorization"));
            inspected = true;
            return ForwarderError.None;
        });
        using var forwarder = new BearerRouteForwarder(transport, provider.GetRequiredService<IForwarderHttpClientFactory>(), provider.GetRequiredService<ITransformBuilder>(), monitor, NullLogger<BearerRouteForwarder>.Instance);
        var http = new DefaultHttpContext();
        http.Request.Method = "GET";
        http.Request.Path = "/api/resource";
        http.Request.Headers.Authorization = "Bearer test_pat_opaque";
        if (pat) http.Items[BearerRouteDefaults.PassThroughAuthorizationItemKey] = true;
        http.Request.Headers[Headers.ForwardedIdentitySignature] = "v1.forged";
        http.Request.Headers["x-cratis-credential-kind"] = "oauth-grant";
        await forwarder.Forward(http, BearerRouteTable.All(config).Single(), identity: null);
        Assert.True(inspected);
    }

    static void Observe(IHttpForwarder transport, Func<CallInfo, Task<ForwarderError>> inspect) =>
        transport.SendAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<HttpMessageInvoker>(), Arg.Any<ForwarderRequestConfig>(), Arg.Any<HttpTransformer>())
            .Returns(call => new ValueTask<ForwarderError>(inspect(call)));
}
