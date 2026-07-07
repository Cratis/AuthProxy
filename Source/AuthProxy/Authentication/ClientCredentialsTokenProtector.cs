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
    static readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);

    readonly ITimeLimitedDataProtector _protector = dataProtectionProvider
        .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.v1")
        .ToTimeLimitedDataProtector();

    /// <summary>
    /// Gets the number of seconds a newly issued token remains valid.
    /// </summary>
    public int ExpiresInSeconds => (int)_tokenLifetime.TotalSeconds;

    /// <summary>
    /// Creates a new bearer token for the supplied service and client identifier.
    /// </summary>
    /// <param name="service">The service the token is scoped to.</param>
    /// <param name="clientId">The verified client identifier.</param>
    /// <returns>The protected bearer token value.</returns>
    public string CreateToken(ConfiguredClientCredentialsService service, string clientId)
    {
        var payload = JsonSerializer.Serialize(
            new ClientCredentialsTokenPayload(service.Name, service.RoutePrefix, clientId),
            _serializerOptions);

        return _protector.Protect(payload, _tokenLifetime);
    }

    /// <summary>
    /// Tries to validate and unprotect a bearer token.
    /// </summary>
    /// <param name="token">The token to validate.</param>
    /// <param name="payload">The unprotected payload.</param>
    /// <returns><see langword="true"/> if the token is valid; otherwise <see langword="false"/>.</returns>
    public bool TryValidate(string token, out ClientCredentialsTokenPayload payload)
    {
        try
        {
            var protectedPayload = _protector.Unprotect(token);
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
