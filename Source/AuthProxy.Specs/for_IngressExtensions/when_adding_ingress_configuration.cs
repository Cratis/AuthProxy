// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Ingress;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

public class when_adding_ingress_configuration : Specification
{
    ServiceProvider _serviceProvider;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:PagesPath"] = "/tmp/custom-pages",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Microsoft"
        });

        builder.AddIngressConfiguration();

        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    [Fact]
    void should_bind_auth_proxy_options()
    {
        var config = _serviceProvider.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue;
        config.PagesPath.ShouldEqual("/tmp/custom-pages");
    }

    /// <summary>
    /// A deployment with no trusted proxies disables forwarded-header processing.
    /// </summary>
    [Fact]
    void should_ignore_forwarded_headers_when_no_trusted_proxies_are_configured()
    {
        var options = _serviceProvider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;

        options.ForwardedHeaders.ShouldEqual(ForwardedHeaders.None);
        options.KnownIPNetworks.Count.ShouldEqual(0);
        options.KnownProxies.Count.ShouldEqual(0);
        options.ForwardLimit.ShouldEqual(1);
    }

    [Fact]
    void should_report_that_no_peer_is_trusted() =>
        _serviceProvider.GetRequiredService<ITrustedProxyPolicy>().TrustsNoOne.ShouldBeTrue();

    [Fact]
    void should_register_tenant_verifier_service() =>
        _serviceProvider.GetRequiredService<ITenantVerifier>().ShouldBeOfExactType<TenantVerifier>();

    [Fact]
    void should_register_error_page_provider_service() =>
        _serviceProvider.GetRequiredService<IErrorPageProvider>().ShouldBeOfExactType<ErrorPageProvider>();

    [Fact]
    void should_register_http_client_factory() =>
        _serviceProvider.GetRequiredService<IHttpClientFactory>().ShouldNotBeNull();
}
