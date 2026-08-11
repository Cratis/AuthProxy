// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_declaring_the_token_endpoint;

/// <summary>
/// Every deployment that has not closed its door keeps the token endpoint exactly as it has always had it,
/// whether or not any service declares client credentials. Removing it from those would be a breaking
/// change for every client already calling it.
/// </summary>
public class and_the_mode_is_public : given.an_admission_policy
{
    bool _declares;

    void Establish() => _config.Admission.Mode = C.AdmissionMode.Public;

    void Because() => _declares = _policy.DeclaresTokenEndpoint(_config);

    [Fact] void should_keep_the_endpoint() => _declares.ShouldBeTrue();
}
