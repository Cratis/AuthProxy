// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A requirement listing no values asks only that the claim be there.
/// <para>
/// That is the shape for an identity provider that emits a claim only for the people who should get in — a
/// group membership mapped to a claim, an entitlement — where enumerating the acceptable values would mean
/// restating the provider's own decision in the proxy, and keeping it restated.
/// </para>
/// </summary>
public class when_a_required_claim_is_present : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _decision;

    void Establish()
    {
        _config = Requiring(Claiming("urn:example:entitlement"));
        CallerCarrying(new Claim("urn:example:entitlement", "anything-at-all"));
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_consider_authorization_configured() => _policy.IsConfigured(_config).ShouldBeTrue();
    [Fact] void should_grant_access() => _decision.IsGranted.ShouldBeTrue();
}
