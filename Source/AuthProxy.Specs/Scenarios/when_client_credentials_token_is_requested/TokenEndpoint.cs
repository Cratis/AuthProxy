// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

/// <summary>
/// Calls the token endpoint the way a client would.
/// </summary>
public static class TokenEndpoint
{
    /// <summary>
    /// Requests tokens with client credentials.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <returns>The response status and parsed body.</returns>
    public static Task<TokenResponse> RequestAsync(HttpClient client) =>
        PostAsync(client, new Dictionary<string, string>
        {
            ["grant_type"] = ClientCredentialsDefaults.GrantType,
            ["service"] = "portal",
            ["client_id"] = "orders-api",
            ["client_secret"] = "super-secret",
        });

    /// <summary>
    /// Exchanges a refresh token.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <param name="refreshToken">The refresh token to present.</param>
    /// <returns>The response status and parsed body.</returns>
    public static Task<TokenResponse> RefreshAsync(HttpClient client, string refreshToken) =>
        PostAsync(client, new Dictionary<string, string>
        {
            ["grant_type"] = ClientCredentialsDefaults.RefreshGrantType,
            ["refresh_token"] = refreshToken,
        });

    static async Task<TokenResponse> PostAsync(HttpClient client, Dictionary<string, string> form)
    {
        var response = await client.PostAsync(WellKnownPaths.Token, new FormUrlEncodedContent(form));
        return new TokenResponse(response.StatusCode, JsonElement.Parse(await response.Content.ReadAsStringAsync()));
    }
}
