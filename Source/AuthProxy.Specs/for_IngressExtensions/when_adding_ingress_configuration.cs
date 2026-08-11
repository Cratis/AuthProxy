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
    /// A deployment that has named no trusted proxies keeps the allow-all posture AuthProxy has always had,
    /// so this release breaks nothing — but it now says so at startup instead of deleting the framework's
    /// loopback default in silence.
    /// </summary>
    /// <remarks>
    /// The middleware runs a peer check only when it knows at least one proxy or network, so an empty pair is
    /// what "believe every caller" means to it. This spec previously asserted the same two zeroes as a
    /// requirement rather than as a compatibility fallback, which is why the boundary was never noticed to be
    /// missing. <c>ForwardLimit</c> is asserted alongside them because a bound-but-unread setting would look
    /// identical here otherwise.
    /// </remarks>
    [Fact]
    void should_fall_back_to_believing_every_caller_when_no_trusted_proxies_are_configured()
    {
        var options = _serviceProvider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;

        options.ForwardedHeaders.ShouldEqual(ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);
        options.KnownIPNetworks.Count.ShouldEqual(0);
        options.KnownProxies.Count.ShouldEqual(0);
        options.ForwardLimit.ShouldEqual(1);
    }

    [Fact]
    void should_report_the_legacy_allow_all_fallback() =>
        _serviceProvider.GetRequiredService<ITrustedProxyPolicy>().IsLegacyAllowAll.ShouldBeTrue();

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
