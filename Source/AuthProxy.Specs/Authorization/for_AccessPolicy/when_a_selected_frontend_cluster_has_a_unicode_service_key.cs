// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

public class when_a_selected_frontend_cluster_has_a_unicode_service_key : given.a_selected_proxy_route
{
    void Establish()
    {
        _context.Request.Path = "/admin/users";
        SelectCluster("key-frontend-cluster");
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_deny_access_without_the_service_claim() => _decision.IsGranted.ShouldBeFalse();
    [Fact] void should_identify_the_service_requirement() => _decision.UnsatisfiedClaim.ShouldEqual("role");
}
