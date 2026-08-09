// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Holds the claim types AuthProxy adds for a GitHub sign-in when the session is allowed to read
/// organization membership.
/// </summary>
/// <remarks>
/// GitHub's user endpoint returns a profile and nothing about where its owner belongs, so no claim about
/// organizations or teams exists to authorize against until one is fetched and added. These are the types
/// under which it is added — the same claims the authorization requirements name, and the same claims the
/// application receives on the forwarded principal.
/// </remarks>
public static class GitHubClaimTypes
{
    /// <summary>
    /// The claim carrying an organization the signed-in user belongs to, as its GitHub login
    /// (for example <c>Cratis</c>). One claim is added per organization.
    /// </summary>
    public const string Organization = "urn:github:organization";

    /// <summary>
    /// The claim carrying a team the signed-in user belongs to, as <c>organization/team-slug</c>
    /// (for example <c>Cratis/planner</c>). One claim is added per team.
    /// </summary>
    /// <remarks>
    /// Qualified by organization because a team slug is only unique within one: two organizations may both
    /// have a <c>developers</c> team, and an unqualified claim would let membership of either satisfy a
    /// requirement meant for one. The slug is the name in the team's URL, which is what an operator has in
    /// front of them when writing the requirement.
    /// </remarks>
    public const string Team = "urn:github:team";
}
