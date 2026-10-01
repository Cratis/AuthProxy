// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

public class when_a_selected_cluster_has_no_configured_service : given.a_selected_proxy_route
{
    void Establish() => SelectCluster("removed-backend-cluster");

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_deny_access_even_without_root_requirements() => _decision.IsGranted.ShouldBeFalse();
}
