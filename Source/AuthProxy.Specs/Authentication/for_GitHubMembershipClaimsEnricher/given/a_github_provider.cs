// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_GitHubMembershipClaimsEnricher.given;

/// <summary>
/// A GitHub OAuth provider configured the way the documentation says to configure it, and an identity for
/// the enricher to add claims to.
/// </summary>
public class a_github_provider : Specification
{
    protected GitHubMembershipClaimsEnricher _enricher;
    protected C.OAuthProvider _provider;
    protected ClaimsIdentity _identity;

    void Establish()
    {
        _enricher = new GitHubMembershipClaimsEnricher(Substitute.For<ILogger<GitHubMembershipClaimsEnricher>>());

        _provider = new C.OAuthProvider
        {
            Name = "GitHub",
            Type = C.OidcProviderType.GitHub,
            AuthorizationEndpoint = "https://github.com/login/oauth/authorize",
            TokenEndpoint = "https://github.com/login/oauth/access_token",
            UserInformationEndpoint = "https://api.github.com/user",
            ClientId = "client-id",
            Scopes = ["read:user", "read:org"],
        };

        _identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "octocat")], "github");
    }

    protected IEnumerable<string> ValuesOf(string claimType) =>
        _identity.FindAll(claimType).Select(_ => _.Value);
}
