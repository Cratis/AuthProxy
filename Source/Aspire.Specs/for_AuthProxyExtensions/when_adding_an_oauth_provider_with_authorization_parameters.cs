// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// Specifies that OAuth authorization-request parameters are emitted as provider configuration.
/// </summary>
public class when_adding_an_oauth_provider_with_authorization_parameters : an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithOAuthProvider(
        "GitHub",
        OidcProviderType.GitHub,
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        "https://api.github.com/user",
        "client-id",
        "client-secret",
        authorizationParameters: new Dictionary<string, string>
        {
            ["prompt"] = "select_account",
            ["audience"] = "workforce"
        });

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_emit_every_authorization_parameter() => new[] { _environment["Cratis__AuthProxy__Authentication__OAuthProviders__0__AuthorizationParameters__prompt"], _environment["Cratis__AuthProxy__Authentication__OAuthProviders__0__AuthorizationParameters__audience"] }.ShouldContainOnly("select_account", "workforce");
}
