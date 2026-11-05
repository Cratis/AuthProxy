// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_the_tenant_endpoint_reuses_a_service_key : given.a_signing_configuration
{
    [Theory]
    [InlineData("https://backend.test/app", "https://backend.test/app/tenants", "spec-backend", true)]
    [InlineData("https://BACKEND.test:443/app/", "https://backend.test/app/tenants", "spec-backend", true)]
    [InlineData("https://backend.test/app", "https://backend.test/app", "spec-backend", true)]
    [InlineData("https://backend.test", "https://backend.test/tenants", "spec-backend", true)]
    [InlineData("https://backend.test/app", "https://backend.test/app/tenants", "another-audience", false)]
    [InlineData("https://backend.test/app", "https://other.test/app/tenants", "spec-backend", false)]
    [InlineData("https://backend.test/app", "http://backend.test/app/tenants", "spec-backend", false)]
    [InlineData("https://backend.test/app", "https://backend.test:444/app/tenants", "spec-backend", false)]
    [InlineData("https://backend.test/app", "https://backend.test/application/tenants", "spec-backend", false)]
    [InlineData("https://backend.test/app", "https://backend.test/APP/tenants", "spec-backend", false)]
    [InlineData("https://backend.test/app", "https://backend.test/app/../other/tenants", "spec-backend", false)]
    [InlineData("", "https://backend.test/app/tenants", "spec-backend", false)]
    public void should_share_only_with_its_own_backend_and_audience(string backend, string endpoint, string audience, bool allowed)
    {
        configuration.Services["main"].Backend = backend.Length == 0 ? null : new() { BaseUrl = backend };
        configuration.TenantResolutions =
        [
            new()
            {
                Strategy = C.TenantSourceIdentifierResolverType.Selection,
                Options = new SelectionOptions
                {
                    TenantsEndpoint = endpoint,
                    ForwardedIdentity = new() { Audience = audience, KeyId = "tenant-key-id", SecretBase64 = settings.SecretBase64 }
                }
            }
        ];
        Validate();
        result.Succeeded.ShouldEqual(allowed);
        if (!allowed)
        {
            result.Failures.Single().ShouldEqual($"{C.AuthProxy.SectionKey}:Services:main:ForwardedIdentity; {C.AuthProxy.SectionKey}:TenantResolutions:0:Options:ForwardedIdentity");
        }
    }

    [Fact]
    void should_not_infer_backend_ownership_from_a_frontend_url()
    {
        configuration.Services["main"].Backend = new() { BaseUrl = "https://backend.test/app" };
        configuration.Services["main"].Frontend = new() { BaseUrl = "https://frontend.test" };
        configuration.TenantResolutions =
        [
            new()
            {
                Strategy = C.TenantSourceIdentifierResolverType.Selection,
                Options = new SelectionOptions { TenantsEndpoint = "https://frontend.test/tenants", ForwardedIdentity = settings }
            }
        ];
        Validate();
        result.Failed.ShouldBeTrue();
    }
}
