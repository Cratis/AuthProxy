// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Maps GitHub onto <see cref="OAuthProvider"/>. GitHub publishes no discovery document, so its endpoints are named.
/// </summary>
public class GitHubProviderTranslation : IProviderTranslation
{
    /// <inheritdoc/>
    public ProviderKind Kind => ProviderKind.GitHub;

    /// <inheritdoc/>
    public IReadOnlyList<string> RequiredKeys => ["clientId", "clientSecret"];

    /// <inheritdoc/>
    public IReadOnlyList<string> OptionalKeys =>
    [
        "authorizationEndpoint",
        "tokenEndpoint",
        "userInformationEndpoint",
        "verifiedEmailEndpoint",
        "issuer",
        "scopes",
        "invitationCompletion"
    ];

    /// <inheritdoc/>
    public void Translate(ProviderValues values, ContractSettings settings)
    {
        var path = settings.NextOAuthProvider();
        var issuer = values.AddressOr("issuer", "https://github.com");
        settings.Set($"{path}:Name", values.Identity);
        settings.Set($"{path}:Type", nameof(OidcProviderType.GitHub));
        settings.Set($"{path}:AuthorizationEndpoint", values.AddressOr("authorizationEndpoint", "https://github.com/login/oauth/authorize"));
        settings.Set($"{path}:TokenEndpoint", values.AddressOr("tokenEndpoint", "https://github.com/login/oauth/access_token"));
        settings.Set($"{path}:UserInformationEndpoint", values.AddressOr("userInformationEndpoint", "https://api.github.com/user"));
        settings.Set($"{path}:VerifiedEmailEndpoint", values.AddressOr("verifiedEmailEndpoint", "https://api.github.com/user/emails"));
        settings.Set($"{path}:ClientId", values.Require("clientId"));
        settings.Set($"{path}:ClientSecret", values.Require("clientSecret"));
        settings.SetList($"{path}:Scopes", values.Scopes("read:user", "user:email"));
        settings.Set($"{path}:ClaimMappings:sub", "id");
        settings.Set($"{path}:ClaimMappings:name", "name");
        settings.Set($"{path}:ClaimMappings:preferred_username", "login");
        settings.Set($"{path}:ClaimMappings:email", "email");

        if (values.InvitationCompletion())
        {
            settings.Set($"{path}:CanonicalIdentity:InvitationCompletionEnabled", "true");
            settings.Set($"{path}:CanonicalIdentity:ProviderKey", values.ProviderKey());
            settings.Set($"{path}:CanonicalIdentity:SubjectClaimType", "sub");
            settings.Set($"{path}:CanonicalIdentity:Issuer", issuer);
        }
    }
}
