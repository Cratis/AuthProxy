// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_declaring_the_token_endpoint;

/// <summary>
/// A closed deployment with nothing to grant does not carry an endpoint that can only refuse. A refusal
/// from it would still be an answer, and the answer names what is running.
/// </summary>
public class and_no_service_declares_client_credentials : given.an_admission_policy
{
    bool _declares;

    void Establish() =>
        _config.Services = new Dictionary<string, C.Service>
        {
            ["app"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" } },
        };

    void Because() => _declares = _policy.DeclaresTokenEndpoint(_config);

    [Fact] void should_leave_the_endpoint_out_of_the_routing_table() => _declares.ShouldBeFalse();
}
