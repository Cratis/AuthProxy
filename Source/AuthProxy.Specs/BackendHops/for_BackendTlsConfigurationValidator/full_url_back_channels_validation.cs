// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BackendHops.given;

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class full_url_back_channels_validation : Specification
{
    protected ValidateOptionsResult _result;
    TestCertificates _certificates;
    C.AuthProxy _configuration;

    protected virtual string Endpoint(string path) => $"https://backend.example{path}";

    protected void Validate() => _result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, _configuration);

    void Establish()
    {
        _certificates = new();
        _configuration = new()
        {
            BackendTls = _certificates.Settings,
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new() { Backend = new() { BaseUrl = Endpoint("/base/") }, ForwardedIdentity = new(), SignInCallback = new() { Path = "/notify" } }
            },
            OnBehalf = new() { Service = "app" },
            Invite = new() { StageUrl = Endpoint("/stage"), ExchangeUrl = Endpoint("/invite/exchange") },
            Link = new() { ExchangeUrl = Endpoint("/link/exchange") },
            SignIn = new() { NotifyUrl = Endpoint("/notify") },
            Admission = new() { Capability = new() { VerifierUrl = Endpoint("/verify") } },
            TenantVerification = new() { UrlTemplate = Endpoint("/tenants/{tenantId}") },
            TenantResolutions = [new() { Options = new SubHostOptions { VerificationUrlTemplate = Endpoint("/subhosts/{tenantId}") } }]
        };
    }

    void Destroy() => _certificates.Dispose();
}
