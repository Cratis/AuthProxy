// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

/// <summary>
/// Crafts a refresh token in the format earlier versions issued.
/// </summary>
public static class EarlierVersionRefreshToken
{
    /// <summary>
    /// Creates an earlier-format refresh token with the given remaining lifetime.
    /// </summary>
    /// <param name="factory">The factory whose host protects the token.</param>
    /// <param name="lifetime">How long the token stays valid.</param>
    /// <returns>The protected token.</returns>
    public static string Create(AuthProxyFactory factory, TimeSpan lifetime)
    {
        var provider = factory.Services.GetRequiredService<IDataProtectionProvider>();
        var protector = provider
            .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.Refresh.v1")
            .ToTimeLimitedDataProtector();
        var json = JsonSerializer.Serialize(new { service = "portal", routePrefix = "/api", clientId = "orders-api" });
        return protector.Protect(json, lifetime);
    }
}
