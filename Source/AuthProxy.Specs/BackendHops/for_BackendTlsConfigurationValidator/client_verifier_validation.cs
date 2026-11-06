// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BackendHops.given;

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class client_verifier_validation : Specification
{
    protected ValidateOptionsResult _result;
    TestCertificates _certificates;
    C.AuthProxy _configuration;

    protected virtual string BackendUrl => "https://backend.example/base/";
    protected virtual string VerificationPath => new C.ServiceClientCredentials().VerificationPath;

    protected void Validate() => _result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, _configuration);

    void Establish()
    {
        _certificates = new();
        _configuration = new()
        {
            BackendTls = _certificates.Settings,
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = new() { BaseUrl = BackendUrl },
                    ForwardedIdentity = new(),
                    ClientCredentials = new() { VerificationPath = VerificationPath }
                }
            }
        };
    }

    void Destroy() => _certificates.Dispose();
}
