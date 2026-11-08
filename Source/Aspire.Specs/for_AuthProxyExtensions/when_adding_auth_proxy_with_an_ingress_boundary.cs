// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_adding_auth_proxy_with_an_ingress_boundary : Specification
{
    const string ModeKey = "Cratis__AuthProxy__Ingress__Mode";
    const string ProxyKey = "Cratis__AuthProxy__Ingress__TrustedProxies__0";

    [Theory]
    [InlineData(false, null, false, false, "TrustAny")]
    [InlineData(true, null, false, false, null)]
    [InlineData(false, "Configured", false, false, "Configured")]
    [InlineData(false, "LoopbackOnly", false, false, "LoopbackOnly")]
    [InlineData(false, null, true, false, null)]
    [InlineData(false, null, false, true, null)]
    [InlineData(true, "TrustAny", false, false, "TrustAny")]
    [InlineData(false, "TrustAny", false, false, "TrustAny")]
    [InlineData(true, null, true, false, null)]
    [InlineData(false, "Configured", true, true, "Configured")]
    public async Task should_preserve_explicit_settings_and_only_default_local_runs(
        bool publish, string? mode, bool fluentProxy, bool environmentProxy, string? expectedMode)
    {
        var builder = publish
            ? DistributedApplication.CreateBuilder(["--operation", "publish"])
            : DistributedApplication.CreateBuilder();
        var resource = builder.AddAuthProxy("auth-proxy");
        if (mode is not null)
        {
            resource.WithEnvironment(ModeKey, mode);
        }
        if (fluentProxy)
        {
            resource.WithTrustedProxies("10.0.0.0/8");
        }
        if (environmentProxy)
        {
            resource.WithEnvironment(ProxyKey, "10.0.0.0/8");
        }

        await using var services = builder.Services.BuildServiceProvider();

        // Only exercise the environment-registration event, without starting Aspire's DCP resources.
        var starting = new BeforeStartEvent(services, new DistributedApplicationModel([]));
        await builder.Eventing.PublishAsync(starting, TestContext.Current.CancellationToken);
        var context = new EnvironmentCallbackContext(new DistributedApplicationExecutionContext(
            publish ? DistributedApplicationOperation.Publish : DistributedApplicationOperation.Run));
        foreach (var annotation in resource.Resource.Annotations.OfType<EnvironmentCallbackAnnotation>())
        {
            await annotation.Callback(context);
        }

        context.EnvironmentVariables.GetValueOrDefault(ModeKey)?.ToString().ShouldEqual(expectedMode);
        if (fluentProxy || environmentProxy)
        {
            context.EnvironmentVariables[ProxyKey].ShouldEqual("10.0.0.0/8");
        }
    }
}
