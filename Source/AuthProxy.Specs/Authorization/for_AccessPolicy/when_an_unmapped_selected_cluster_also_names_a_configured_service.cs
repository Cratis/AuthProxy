// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

public class when_an_unmapped_selected_cluster_also_names_a_configured_service : given.a_selected_proxy_route
{
    void Establish()
    {
        CallerCarrying(new Claim("role", "admin"));
        _context.Request.Headers[Headers.ServiceId] = "\u212Aey";
        SelectCluster("removed-backend-cluster");
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_deny_access_instead_of_applying_the_named_service_requirements() => _decision.IsGranted.ShouldBeFalse();
}
