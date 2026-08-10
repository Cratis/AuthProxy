// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A deployment that declares nothing is a deployment this feature does not exist in.
/// <para>
/// Every AuthProxy already running predates first-gate authorization, and none of them will declare a
/// requirement the day they take the upgrade. The one outcome that would matter is the one where an empty
/// configuration started meaning "nobody satisfies anything" — an instant, total outage on a version bump.
/// So the empty case is pinned separately from the satisfied case: not merely granted, but not even
/// recognized as configured, which is what keeps the evaluation off the request path entirely.
/// </para>
/// </summary>
public class when_nothing_is_required : given.an_access_policy
{
    C.AuthProxy _config;
    bool _isConfigured;
    AccessDecision _decision;

    void Establish()
    {
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" } },
            },
        };

        CallerCarrying(new Claim(ClaimTypes.NameIdentifier, "someone"));
    }

    void Because()
    {
        _isConfigured = _policy.IsConfigured(_config);
        _decision = _policy.Evaluate(_context, _config);
    }

    [Fact] void should_not_consider_authorization_configured() => _isConfigured.ShouldBeFalse();
    [Fact] void should_grant_access() => _decision.IsGranted.ShouldBeTrue();
}
