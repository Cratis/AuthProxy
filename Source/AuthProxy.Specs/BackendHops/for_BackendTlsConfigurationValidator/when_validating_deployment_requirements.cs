// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_validating_deployment_requirements
{
    [Theory]
    [InlineData(false, false, false, false, true)]
    [InlineData(false, false, true, false, true)]
    [InlineData(false, true, false, false, true)]
    [InlineData(false, false, false, true, true)]
    [InlineData(true, false, false, false, false)]
    [InlineData(true, true, false, false, false)]
    [InlineData(true, true, true, false, true)]
    [InlineData(true, false, false, true, true)]
    public void should_require_https_and_client_authentication_only_for_signed_production_hops(bool signingEnabled, bool https, bool client, bool local, bool succeeds)
    {
        using var certificates = new given.TestCertificates();
        var options = new C.AuthProxy
        {
            Profile = local ? C.DeploymentProfile.LocalDevelopment : C.DeploymentProfile.Default,
            BackendTls = client ? certificates.Settings : new(),
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new() { Backend = new() { BaseUrl = https ? "https://localhost" : "http://localhost" }, ForwardedIdentity = signingEnabled ? new() : null }
            }
        };
        new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options).Succeeded.ShouldEqual(succeeds);
    }

    [Theory]
    [InlineData(false, false, true, false)]
    [InlineData(true, false, true, false)]
    [InlineData(false, true, false, false)]
    [InlineData(true, true, false, false)]
    [InlineData(false, true, true, true)]
    [InlineData(true, true, true, true)]
    public void should_cover_frontends_whether_or_not_the_service_has_a_backend(bool backend, bool https, bool client, bool succeeds)
    {
        using var certificates = new given.TestCertificates();
        var options = new C.AuthProxy
        {
            BackendTls = client ? certificates.Settings : new(),
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = backend ? new() { BaseUrl = "https://backend.example" } : null,
                    Frontend = new() { BaseUrl = https ? "https://frontend.example" : "http://frontend.example" },
                    ForwardedIdentity = new()
                }
            }
        };
        var result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options);
        result.Succeeded.ShouldEqual(succeeds);
        if (!succeeds) string.Join(';', result.Failures).ShouldContain("Services:app:Frontend:BaseUrl");
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void should_allow_http_frontends_without_client_authentication_when_unsigned_or_local(bool backend, bool local)
    {
        var options = new C.AuthProxy
        {
            Profile = local ? C.DeploymentProfile.LocalDevelopment : C.DeploymentProfile.Default,
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = backend ? new() { BaseUrl = "https://backend.example" } : null,
                    Frontend = new() { BaseUrl = local ? "http://localhost" : "http://frontend.example" },
                    ForwardedIdentity = local ? new() : null
                }
            }
        };
        new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options).Succeeded.ShouldBeTrue();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void should_require_https_for_a_tenant_list_when_signing_is_configured(bool signingEnabled)
    {
        var options = new C.AuthProxy
        {
            TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.Selection, Options = new SelectionOptions { TenantsEndpoint = "http://localhost/tenants", ForwardedIdentity = signingEnabled ? new() : null } }]
        };
        var result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options);
        result.Failed.ShouldEqual(signingEnabled);
        if (signingEnabled) string.Join(';', result.Failures!).ShouldContain("TenantResolutions:0:Options:TenantsEndpoint");
    }

    [Fact]
    public void should_not_let_local_development_ignore_an_invalid_configured_certificate()
    {
        var options = new C.AuthProxy { Profile = C.DeploymentProfile.LocalDevelopment, BackendTls = new() { ClientCertificate = new() } };
        new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options).Failed.ShouldBeTrue();
    }

    [Fact]
    public void should_refuse_an_unknown_profile_or_tight_reload_loop()
    {
        var options = new C.AuthProxy { Profile = (C.DeploymentProfile)99, BackendTls = new() { ReloadInterval = TimeSpan.Zero } };
        new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options).Failures!.Count().ShouldEqual(2);
    }
}
