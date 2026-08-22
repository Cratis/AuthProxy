// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// Specifies canonical OAuth configuration at an accumulated provider index without losing OAuth settings.
/// </summary>
public class when_adding_a_canonical_oauth_provider_after_an_existing_provider : an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithOAuthProvider(
            "Legacy",
            OidcProviderType.Custom,
            "https://legacy.example.com/authorize",
            "https://legacy.example.com/token",
            "https://legacy.example.com/user",
            "legacy-client",
            "legacy-secret");
        _resource.WithCanonicalOAuthProvider(
            "GitHub Enterprise",
            OidcProviderType.GitHub,
            "https://github.example.com/authorize",
            "https://github.example.com/token",
            "https://github.example.com/user",
            "client-id",
            "client-secret",
            "github-workforce",
            "id",
            "https://github.example.com",
            ["read:user", "read:org"],
            new Dictionary<string, string> { ["oid"] = "id", ["email"] = "mail" },
            new Dictionary<string, string> { ["prompt"] = "select_account", ["audience"] = "workforce" });
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_emit_the_canonical_tuple_at_the_accumulated_index() => _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__CanonicalIdentity__ProviderKey"].ShouldEqual("github-workforce");
    [Fact] void should_emit_the_explicit_issuer() => _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__CanonicalIdentity__Issuer"].ShouldEqual("https://github.example.com");
    [Fact] void should_preserve_all_scopes() => new[] { _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__Scopes__0"], _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__Scopes__1"] }.ShouldContainOnly("read:user", "read:org");
    [Fact] void should_preserve_claim_mappings() => new[] { _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__ClaimMappings__oid"], _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__ClaimMappings__email"] }.ShouldContainOnly("id", "mail");
    [Fact] void should_preserve_authorization_parameters() => new[] { _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__AuthorizationParameters__prompt"], _environment["Cratis__AuthProxy__Authentication__OAuthProviders__1__AuthorizationParameters__audience"] }.ShouldContainOnly("select_account", "workforce");
}
