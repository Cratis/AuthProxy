// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class identity_back_channels : Specification
{
    protected C.AuthProxy _configuration;
    protected ValidateOptionsResult _result;

    protected virtual bool SigningConfigured => true;
    protected virtual bool RequireTls => false;
    protected virtual C.DeploymentProfile Profile => C.DeploymentProfile.Default;

    void Establish() => _configuration = new()
    {
        Profile = Profile,
        BackendTls = new() { RequireTlsOnIdentityHops = RequireTls },
        Services = new Dictionary<string, C.Service>
        {
            ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = SigningConfigured ? new() : null },
            ["callbacks"] = new() { Backend = new() { BaseUrl = "http://localhost:8080" }, SignInCallback = new(), ClientCredentials = new() }
        },
        OnBehalf = new() { Service = "callbacks" },
        Invite = new() { StageUrl = "http://localhost:8081/stage", ExchangeUrl = "http://localhost:8081/exchange" },
        Link = new() { ExchangeUrl = "http://localhost:8082/exchange" },
        SignIn = new() { NotifyUrl = "http://localhost:8083/notify" },
        Admission = new() { Capability = new() { VerifierUrl = "http://localhost:8084/verify" } },
        TenantVerification = new() { UrlTemplate = "http://localhost:8085/tenants/{tenantId}" },
        TenantResolutions = [new() { Options = new SubHostOptions { VerificationUrlTemplate = "http://localhost:8086/tenants/{tenantId}" } }]
    };
}
