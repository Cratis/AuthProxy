// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Creates and validates AuthProxy-issued bearer tokens for the client-credentials flow.
/// </summary>
/// <remarks>
/// A chain of refreshed tokens (a family) has one absolute deadline, set when the family starts and carried
/// unchanged by every refresh token, so refreshing never extends it. Access tokens never outlive it either.
/// </remarks>
/// <param name="dataProtectionProvider">Creates the data protector used for AuthProxy-issued bearer tokens.</param>
/// <param name="timeProvider">The clock used for token expiry.</param>
public class ClientCredentialsTokenProtector(
    IDataProtectionProvider dataProtectionProvider,
    TimeProvider timeProvider)
{
    static readonly TimeSpan _tokenLifetime = TimeSpan.FromHours(1);
    static readonly TimeSpan _refreshTokenLifetime = TimeSpan.FromDays(30);
    static readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);

    readonly ITimeLimitedDataProtector _protector = dataProtectionProvider
        .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.v1")
        .ToTimeLimitedDataProtector();

    readonly IDataProtector _issuedProtector = dataProtectionProvider
        .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.v1")
        .CreateProtector("Microsoft.AspNetCore.DataProtection.TimeLimitedDataProtector.v1");

    /// <summary>
    /// Reads refresh tokens issued by earlier versions. They are never issued; their own expiry is their family deadline.
    /// </summary>
    readonly ITimeLimitedDataProtector _legacyRefreshProtector = dataProtectionProvider
        .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.Refresh.v1")
        .ToTimeLimitedDataProtector();

    readonly IDataProtector _refreshProtector = dataProtectionProvider
        .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.Refresh.v2");

    /// <summary>
    /// Initializes a new instance of the <see cref="ClientCredentialsTokenProtector"/> class using the system clock.
    /// </summary>
    /// <param name="dataProtectionProvider">Creates the data protector used for AuthProxy-issued bearer tokens.</param>
    public ClientCredentialsTokenProtector(IDataProtectionProvider dataProtectionProvider)
        : this(dataProtectionProvider, TimeProvider.System)
    {
    }

    /// <summary>
    /// Gets the number of seconds an access token remains valid when its family deadline does not come first.
    /// </summary>
    public int ExpiresInSeconds => (int)_tokenLifetime.TotalSeconds;

    /// <summary>
    /// Gets the number of seconds a refresh token remains valid when its family deadline does not come first.
    /// </summary>
    public int RefreshExpiresInSeconds => (int)_refreshTokenLifetime.TotalSeconds;

    /// <summary>
    /// Starts a new family of refreshed tokens, counting its lifetime from now.
    /// </summary>
    /// <param name="service">The service the family is scoped to.</param>
    /// <returns>The absolute deadline of the family.</returns>
    public DateTimeOffset StartFamily(ConfiguredClientCredentialsService service) =>
        timeProvider.GetUtcNow().Add(service.RefreshTokenFamilyLifetime);

    /// <summary>
    /// Issues an access token and a refresh token that both end no later than the family deadline.
    /// </summary>
    /// <param name="service">The service the tokens are scoped to.</param>
    /// <param name="clientId">The verified client identifier.</param>
    /// <param name="tenant">The tenant resolved from the downstream verification response, when one was returned.</param>
    /// <param name="familyExpiresAt">The absolute deadline of the family.</param>
    /// <returns>The issued tokens.</returns>
    public ClientCredentialsIssuedTokens Issue(
        ConfiguredClientCredentialsService service,
        string clientId,
        string? tenant,
        DateTimeOffset familyExpiresAt)
    {
        var now = timeProvider.GetUtcNow();
        var accessExpiresAt = Earliest(now.Add(_tokenLifetime), familyExpiresAt);
        var refreshExpiresAt = Earliest(now.Add(_refreshTokenLifetime), familyExpiresAt);

        var refreshContent = new ClientCredentialsRefreshTokenContent(
            service.Name,
            service.RoutePrefix,
            clientId,
            tenant,
            refreshExpiresAt,
            familyExpiresAt);

        return new ClientCredentialsIssuedTokens(
            _protector.Protect(Serialize(new ClientCredentialsTokenPayload(service.Name, service.RoutePrefix, clientId, tenant)), accessExpiresAt),
            (int)Math.Max(0, (accessExpiresAt - now).TotalSeconds),
            _refreshProtector.Protect(JsonSerializer.Serialize(refreshContent, _serializerOptions)));
    }

    /// <summary>
    /// Creates a new access token for the supplied service and client identifier.
    /// </summary>
    /// <param name="service">The service the token is scoped to.</param>
    /// <param name="clientId">The verified client identifier.</param>
    /// <param name="tenant">The tenant resolved from the downstream verification response, when one was returned.</param>
    /// <returns>The protected access token value.</returns>
    public string CreateToken(ConfiguredClientCredentialsService service, string clientId, string? tenant = null) =>
        Issue(service, clientId, tenant, StartFamily(service)).AccessToken;

    /// <summary>
    /// Creates a refresh token that starts a new family for the supplied service and client identifier.
    /// </summary>
    /// <param name="service">The service the token is scoped to.</param>
    /// <param name="clientId">The verified client identifier.</param>
    /// <param name="tenant">The tenant resolved from the downstream verification response, when one was returned.</param>
    /// <returns>The protected refresh token value.</returns>
    public string CreateRefreshToken(ConfiguredClientCredentialsService service, string clientId, string? tenant = null) =>
        Issue(service, clientId, tenant, StartFamily(service)).RefreshToken;

    /// <summary>
    /// Recognizes an access token minted by this deployment, regardless of expiry. Never authorizes its use.
    /// </summary>
    /// <param name="token">The protected access token value.</param>
    /// <returns>Whether the token can be unprotected with this deployment's access-token purposes.</returns>
    public bool IsIssued(string token)
    {
        try
        {
            // The time-limited envelope includes a binary expiry header, not UTF-8 text.
            _issuedProtector.Unprotect(WebEncoders.Base64UrlDecode(token));
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Tries to validate and unprotect an access token.
    /// </summary>
    /// <param name="token">The token to validate.</param>
    /// <param name="payload">The unprotected payload.</param>
    /// <returns><see langword="true"/> if the token is valid; otherwise <see langword="false"/>.</returns>
    public bool TryValidate(string token, out ClientCredentialsTokenPayload payload) =>
        TryValidate(token, out payload, out _);

    /// <summary>
    /// Tries to validate and unprotect a refresh token. The payload carries the deadline of the token's family.
    /// </summary>
    /// <param name="token">The token to validate.</param>
    /// <param name="payload">The unprotected payload.</param>
    /// <returns><see langword="true"/> if the token is valid; otherwise <see langword="false"/>.</returns>
    public bool TryValidateRefreshToken(string token, out ClientCredentialsTokenPayload payload) =>
        TryUnprotectRefreshToken(token, out payload) || TryUnprotectLegacyRefreshToken(token, out payload);

    /// <summary>Validates an access token and retains its protected deadline for a request-local handoff.</summary>
    /// <param name="token">The access token.</param>
    /// <param name="payload">The verified payload.</param>
    /// <param name="expiresAt">The deadline protected alongside the payload.</param>
    /// <returns>Whether the token is valid.</returns>
    internal bool TryValidate(string token, out ClientCredentialsTokenPayload payload, out DateTimeOffset expiresAt) =>
        TryUnprotect(_protector, token, out payload, out expiresAt);

    static DateTimeOffset Earliest(DateTimeOffset first, DateTimeOffset second) => first <= second ? first : second;

    static string Serialize(ClientCredentialsTokenPayload payload) => JsonSerializer.Serialize(payload, _serializerOptions);

    bool TryUnprotect(ITimeLimitedDataProtector protector, ProtectedToken token, out ClientCredentialsTokenPayload payload, out DateTimeOffset expiresAt)
    {
        expiresAt = default;
        payload = default!;
        try
        {
            var protectedPayload = protector.Unprotect(token.Value, out expiresAt);
            if (HasPassed(expiresAt))
            {
                return false;
            }

            var deserialized = JsonSerializer.Deserialize<ClientCredentialsTokenPayload>(protectedPayload, _serializerOptions);
            if (deserialized is null)
            {
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

    bool TryUnprotectRefreshToken(ProtectedToken token, out ClientCredentialsTokenPayload payload)
    {
        payload = default!;
        try
        {
            var content = JsonSerializer.Deserialize<ClientCredentialsRefreshTokenContent>(_refreshProtector.Unprotect(token.Value), _serializerOptions);
            if (content?.ExpiresAt is not { } expiresAt || content.FamilyExpiresAt is not { } familyExpiresAt)
            {
                return false;
            }

            if (HasPassed(expiresAt) || HasPassed(familyExpiresAt))
            {
                return false;
            }

            payload = new ClientCredentialsTokenPayload(content.Service, content.RoutePrefix, content.ClientId, content.Tenant)
            {
                FamilyExpiresAt = familyExpiresAt,
            };
            return true;
        }
        catch
        {
            return false;
        }
    }

    bool TryUnprotectLegacyRefreshToken(ProtectedToken token, out ClientCredentialsTokenPayload payload)
    {
        payload = default!;
        try
        {
            var unprotected = _legacyRefreshProtector.Unprotect(token.Value, out var expiration);
            var deserialized = JsonSerializer.Deserialize<ClientCredentialsTokenPayload>(unprotected, _serializerOptions);
            if (deserialized is null || HasPassed(expiration))
            {
                return false;
            }

            payload = deserialized with { FamilyExpiresAt = expiration };
            return true;
        }
        catch
        {
            return false;
        }
    }

    bool HasPassed(DateTimeOffset deadline) => timeProvider.GetUtcNow() >= deadline;
}
