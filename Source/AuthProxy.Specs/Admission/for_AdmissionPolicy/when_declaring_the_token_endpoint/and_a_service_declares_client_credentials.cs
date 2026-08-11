// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_declaring_the_token_endpoint;

/// <summary>
/// A closed deployment that does grant client credentials keeps the endpoint. Closing the interactive
/// contract says nothing about the back channel, which has always required a credential to answer at all.
/// </summary>
public class and_a_service_declares_client_credentials : given.an_admission_policy
{
    bool _declares;

    void Establish() =>
        _config.Services = new Dictionary<string, C.Service>
        {
            ["app"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                ClientCredentials = new C.ServiceClientCredentials(),
            },
        };

    void Because() => _declares = _policy.DeclaresTokenEndpoint(_config);

    [Fact] void should_keep_the_endpoint() => _declares.ShouldBeTrue();
}
