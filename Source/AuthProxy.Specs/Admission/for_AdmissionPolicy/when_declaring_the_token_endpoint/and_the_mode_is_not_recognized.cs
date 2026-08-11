// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_declaring_the_token_endpoint;

/// <summary>
/// The endpoint is kept for deployments that are public, not for deployments that merely are not
/// capability-only. Read the other way round, an unrecognized mode would be the single value that hands a
/// closed deployment an endpoint back — the same fail-open the gate itself is asked to avoid, arriving
/// through the other predicate on this policy.
/// </summary>
public class and_the_mode_is_not_recognized : given.an_admission_policy
{
    bool _declares;

    void Establish()
    {
        _config.Admission.Mode = (C.AdmissionMode)2;
        _config.Services = new Dictionary<string, C.Service>
        {
            ["app"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" } },
        };
    }

    void Because() => _declares = _policy.DeclaresTokenEndpoint(_config);

    [Fact] void should_leave_the_endpoint_out_of_the_routing_table() => _declares.ShouldBeFalse();
}
