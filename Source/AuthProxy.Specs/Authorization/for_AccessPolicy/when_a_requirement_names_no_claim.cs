// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A requirement that names no claim denies rather than being skipped.
/// <para>
/// Startup validation refuses such a configuration outright, so this is the second line rather than the
/// first — but it is the line that decides which way the failure falls. Discarding an unusable requirement
/// is how an unusable <c>AnonymousPaths</c> entry is handled, and it is fail-closed <em>there</em> because
/// discarding leaves the path authenticated. Here the same move would leave the gate open, so the
/// direction has to be the other one: unsatisfiable means nobody satisfies it.
/// </para>
/// </summary>
public class when_a_requirement_names_no_claim : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _decision;

    void Establish()
    {
        _config = Requiring(Claiming("   "));
        CallerCarrying(new Claim("urn:github:organization", "Cratis"));
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_deny_access() => _decision.IsGranted.ShouldBeFalse();
}
