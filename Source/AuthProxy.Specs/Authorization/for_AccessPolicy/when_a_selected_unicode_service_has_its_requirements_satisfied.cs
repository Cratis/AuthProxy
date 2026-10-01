// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

public class when_a_selected_unicode_service_has_its_requirements_satisfied : given.a_selected_proxy_route
{
    void Establish()
    {
        CallerCarrying(new Claim("role", "admin"));
        SelectCluster("key-backend-cluster");
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_grant_access() => _decision.IsGranted.ShouldBeTrue();
}
