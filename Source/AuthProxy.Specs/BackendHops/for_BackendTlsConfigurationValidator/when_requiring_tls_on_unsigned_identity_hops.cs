// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_requiring_tls_on_unsigned_identity_hops
{
    [Theory]
    [InlineData(false, "http://target.example", false, true)]
    [InlineData(true, "http://target.example", false, false)]
    [InlineData(true, "https://target.example", false, true)]
    [InlineData(true, "http://localhost", true, true)]
    [InlineData(true, "http://target.example", true, false)]
    [InlineData(true, "http://localhost", false, false)]
    public void should_validate_every_destination(bool requireTls, string address, bool local, bool succeeds)
    {
        var options = new C.AuthProxy
        {
            Profile = local ? C.DeploymentProfile.LocalDevelopment : C.DeploymentProfile.Default,
            BackendTls = new() { RequireTlsOnIdentityHops = requireTls },
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = new() { BaseUrl = address },
                    Frontend = new() { BaseUrl = address },
                    SignInCallback = new(),
                    ClientCredentials = new() { VerificationPath = $"{address}/verify" }
                },
                ["frontend"] = new() { Frontend = new() { BaseUrl = address } }
            },
            OnBehalf = new() { Service = "app" },
            Invite = new() { StageUrl = $"{address}/stage", ExchangeUrl = $"{address}/exchange" },
            Link = new() { ExchangeUrl = $"{address}/link" },
            SignIn = new() { NotifyUrl = $"{address}/notify" },
            Admission = new() { Capability = new() { VerifierUrl = $"{address}/capability" } },
            TenantVerification = new() { UrlTemplate = $"{address}/tenants/{{tenantId}}" },
            TenantResolutions =
            [
                new() { Strategy = C.TenantSourceIdentifierResolverType.Selection, Options = new SelectionOptions { TenantsEndpoint = $"{address}/tenants" } },
                new() { Options = new SubHostOptions { VerificationUrlTemplate = $"{address}/tenants/{{tenantId}}" } }
            ]
        };

        var result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, options);
        result.Succeeded.ShouldEqual(succeeds);
        if (succeeds) return;
        var failures = string.Join(';', result.Failures!);
        failures.ShouldContain("Services:app:Backend:BaseUrl");
        failures.ShouldContain("Services:app:Frontend:BaseUrl");
        failures.ShouldContain("Services:frontend:Frontend:BaseUrl");
        failures.ShouldContain("Services:app:ClientCredentials:VerificationPath");
        failures.ShouldContain("Invite:StageUrl");
        failures.ShouldContain("Invite:ExchangeUrl");
        failures.ShouldContain("Link:ExchangeUrl");
        failures.ShouldContain("SignIn:NotifyUrl");
        failures.ShouldContain("Admission:Capability:VerifierUrl");
        failures.ShouldContain("TenantVerification:UrlTemplate");
        failures.ShouldContain("TenantResolutions:0:Options:TenantsEndpoint");
        failures.ShouldContain("TenantResolutions:1:Options:VerificationUrlTemplate");
        failures.ShouldNotContain(address);
    }
}
