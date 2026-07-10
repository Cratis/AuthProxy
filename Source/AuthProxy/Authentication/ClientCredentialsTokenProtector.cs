// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Creates and validates AuthProxy-issued bearer tokens for the client-credentials flow.
/// </summary>
/// <param name="dataProtectionProvider">Creates the data protector used for AuthProxy-issued bearer tokens.</param>
public class ClientCredentialsTokenProtector(
    IDataProtectionProvider dataProtectionProvider)
{
    static readonly TimeSpan _tokenLifetime = TimeSpan.FromHours(1);
    static readonly TimeSpan _refreshTokenLifetime = TimeSpan.FromDays(30);
    static readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);

    readonly ITimeLimitedDataProtector _protector = dataProtectionProvider
        .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.v1")
        .ToTimeLimitedDataProtector();

    readonly ITimeLimitedDataProtector _refreshProtector = dataProtectionProvider
        .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.Refresh.v1")
        .ToTimeLimitedDataProtector();

    /// <summary>
    /// Gets the number of seconds a newly issued access token remains valid.
    /// </summary>
    public int ExpiresInSeconds => (int)_tokenLifetime.TotalSeconds;

    /// <summary>
    /// Gets the number of seconds a newly issued refresh token remains valid.
    /// </summary>
    public int RefreshExpiresInSeconds => (int)_refreshTokenLifetime.TotalSeconds;

    /// <summary>
    /// Creates a new access token for the supplied service and client identifier.
    /// </summary>
    /// <param name="service">The service the token is scoped to.</param>
    /// <param name="clientId">The verified client identifier.</param>
    /// <param name="tenant">The tenant resolved from the downstream verification response, when one was returned.</param>
    /// <returns>The protected access token value.</returns>
    public string CreateToken(ConfiguredClientCredentialsService service, string clientId, string? tenant = null) =>
        _protector.Protect(Serialize(service, clientId, tenant), _tokenLifetime);

    /// <summary>
    /// Creates a new refresh token for the supplied service and client identifier.
    /// </summary>
    /// <param name="service">The service the token is scoped to.</param>
    /// <param name="clientId">The verified client identifier.</param>
    /// <param name="tenant">The tenant resolved from the downstream verification response, when one was returned.</param>
    /// <returns>The protected refresh token value.</returns>
    public string CreateRefreshToken(ConfiguredClientCredentialsService service, string clientId, string? tenant = null) =>
        _refreshProtector.Protect(Serialize(service, clientId, tenant), _refreshTokenLifetime);

    /// <summary>
    /// Tries to validate and unprotect an access token.
    /// </summary>
    /// <param name="token">The token to validate.</param>
    /// <param name="payload">The unprotected payload.</param>
    /// <returns><see langword="true"/> if the token is valid; otherwise <see langword="false"/>.</returns>
    public bool TryValidate(string token, out ClientCredentialsTokenPayload payload) =>
        TryUnprotect(_protector, token, out payload);

    /// <summary>
    /// Tries to validate and unprotect a refresh token.
    /// </summary>
    /// <param name="token">The token to validate.</param>
    /// <param name="payload">The unprotected payload.</param>
    /// <returns><see langword="true"/> if the token is valid; otherwise <see langword="false"/>.</returns>
    public bool TryValidateRefreshToken(string token, out ClientCredentialsTokenPayload payload) =>
        TryUnprotect(_refreshProtector, token, out payload);

    static string Serialize(ConfiguredClientCredentialsService service, string clientId, string? tenant) =>
        JsonSerializer.Serialize(
            new ClientCredentialsTokenPayload(service.Name, service.RoutePrefix, clientId, tenant),
            _serializerOptions);

    static bool TryUnprotect(ITimeLimitedDataProtector protector, string token, out ClientCredentialsTokenPayload payload)
    {
        try
        {
            var protectedPayload = protector.Unprotect(token);
            var deserialized = JsonSerializer.Deserialize<ClientCredentialsTokenPayload>(protectedPayload, _serializerOptions);
            if (deserialized is null)
            {
                payload = default!;
                return false;
            }

            payload = deserialized;
            return true;
        }
        catch
        {
            payload = default!;
            return false;
        }
    }
}
