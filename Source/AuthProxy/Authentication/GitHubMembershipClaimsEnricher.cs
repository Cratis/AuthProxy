// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Adds a claim per GitHub organization and per GitHub team the signing-in user belongs to, so the ordinary
/// claim requirements can gate on membership.
/// </summary>
/// <remarks>
/// GitHub's user endpoint — the one <see cref="C.OAuthProvider.UserInformationEndpoint"/> names — returns a
/// profile and nothing about membership, so there is no claim to match on and no mapping that could produce
/// one. Membership lives behind <c>/user/orgs</c> and <c>/user/teams</c>, which is why gating on a GitHub
/// organization is not a matter of configuration alone.
/// <para>
/// Fetching it once, at sign-in, and turning it into claims is what keeps a single authorization mechanism:
/// the requirement that names <see cref="GitHubClaimTypes.Organization"/> is the same kind of requirement as
/// one naming a role from an OIDC provider, evaluated by the same code. The application behind the proxy
/// gets the membership too, on the forwarded principal, without asking GitHub itself.
/// </para>
/// <para>
/// The alternative — a GitHub-specific rule calling GitHub during authorization — would need a second rule
/// type, a second evaluator, and a live API call on requests rather than on sign-ins.
/// </para>
/// </remarks>
/// <param name="logger">The logger.</param>
public class GitHubMembershipClaimsEnricher(ILogger<GitHubMembershipClaimsEnricher> logger) : IProviderClaimsEnricher
{
    /// <summary>
    /// The scopes that let a token see the organizations and teams a user belongs to.
    /// </summary>
    /// <remarks>
    /// This is also the opt-in. Without one of these GitHub answers <c>/user/orgs</c> with public
    /// memberships only and refuses <c>/user/teams</c> outright, so membership claims would be
    /// misleading where they were not simply absent. Requesting the scope is therefore the same statement
    /// as asking for the claims, and a deployment that does not request it makes no extra calls and gets
    /// exactly the sign-in it got before.
    /// </remarks>
    static readonly string[] _organizationReadScopes = ["read:org", "write:org", "admin:org"];

    /// <inheritdoc/>
    public bool CanEnrich(C.OAuthProvider provider) =>
        provider.Type == C.OidcProviderType.GitHub
        && provider.Scopes.Any(scope => _organizationReadScopes.Contains(scope?.Trim() ?? string.Empty, StringComparer.OrdinalIgnoreCase));

    /// <inheritdoc/>
    public async Task Enrich(
        ClaimsIdentity identity,
        C.OAuthProvider provider,
        HttpClient backchannel,
        string accessToken,
        CancellationToken cancellationToken)
    {
        if (!TryResolveResource(provider, "orgs", out var organizations)
            || !TryResolveResource(provider, "teams", out var teams))
        {
            logger.MembershipEndpointUnresolvable(provider.Name);
            return;
        }

        Add(identity, GitHubClaimTypes.Organization, await GitHubPagedResourceReader.Read(backchannel, accessToken, organizations, SelectOrganization, logger, cancellationToken));
        Add(identity, GitHubClaimTypes.Team, await GitHubPagedResourceReader.Read(backchannel, accessToken, teams, SelectTeam, logger, cancellationToken));
    }

    /// <summary>
    /// Resolves a membership collection endpoint from the configured user-information endpoint.
    /// </summary>
    /// <param name="provider">The provider whose endpoints to read.</param>
    /// <param name="resource">The collection under the user endpoint (<c>orgs</c> or <c>teams</c>).</param>
    /// <param name="url">The resolved URL when the endpoint is usable.</param>
    /// <returns><see langword="true"/> when the URL could be resolved; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Derived rather than configured, so GitHub Enterprise works without a second setting: the collections
    /// sit directly under whatever user endpoint is already configured, whether that is
    /// <c>https://api.github.com/user</c> or <c>https://github.example.com/api/v3/user</c>.
    /// </remarks>
    static bool TryResolveResource(C.OAuthProvider provider, string resource, out Uri url)
    {
        url = null!;

        if (!Uri.TryCreate($"{provider.UserInformationEndpoint?.TrimEnd('/')}/{resource}", UriKind.Absolute, out var resolved))
        {
            return false;
        }

        url = resolved;
        return true;
    }

    static string? SelectOrganization(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty("login", out var login)
        && login.ValueKind == JsonValueKind.String
            ? login.GetString()
            : null;

    static string? SelectTeam(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty("slug", out var slug)
        && slug.ValueKind == JsonValueKind.String
        && element.TryGetProperty("organization", out var organization)
        && organization.ValueKind == JsonValueKind.Object
        && organization.TryGetProperty("login", out var login)
        && login.ValueKind == JsonValueKind.String
            ? $"{login.GetString()}/{slug.GetString()}"
            : null;

    static void Add(ClaimsIdentity identity, string claimType, IEnumerable<string> values)
    {
        foreach (var value in values.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!identity.HasClaim(claim => string.Equals(claim.Type, claimType, StringComparison.OrdinalIgnoreCase)
                && string.Equals(claim.Value, value, StringComparison.OrdinalIgnoreCase)))
            {
                identity.AddClaim(new Claim(claimType, value));
            }
        }
    }
}
