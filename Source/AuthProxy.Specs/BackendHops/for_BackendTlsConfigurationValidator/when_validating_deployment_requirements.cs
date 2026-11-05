// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_validating_deployment_requirements
{
    [Theory]
    [InlineData(false, false, false, false, true)]
    [InlineData(false, false, true, false, true)]
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

    [Fact]
    public void should_refuse_a_signed_http_tenant_list_even_without_signed_services()
    {
        var options = new C.AuthProxy
        {
            TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.Selection, Options = new SelectionOptions { TenantsEndpoint = "http://localhost/tenants", ForwardedIdentity = new() } }]
        };
        var result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options);
        result.Failed.ShouldBeTrue();
        string.Join(';', result.Failures!).ShouldContain("TenantResolutions:0:Options:TenantsEndpoint");
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
