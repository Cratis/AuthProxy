// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Represents the Microsoft Client Principal Data definition used by Azure Static Web Apps,
/// Container Apps and App Service. The ingress builds this from the authenticated
/// <see cref="System.Security.Claims.ClaimsPrincipal"/> and forwards it as
/// <c>x-ms-client-principal</c> (base64-encoded JSON) on every proxied request.
/// </summary>
/// <remarks>
/// See https://learn.microsoft.com/azure/static-web-apps/user-information for the
/// authoritative definition.
/// </remarks>
public class ClientPrincipal
{
    static readonly JsonSerializerOptions _serializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Gets or sets the identity provider (e.g. <c>aad</c>, <c>github</c>).</summary>
    [JsonPropertyName("identityProvider")]
    public string IdentityProvider { get; set; } = string.Empty;

    /// <summary>Gets or sets the unique user identifier from the identity provider.</summary>
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = string.Empty;

    /// <summary>Gets or sets the human-readable user name / email.</summary>
    [JsonPropertyName("userDetails")]
    public string UserDetails { get; set; } = string.Empty;

    /// <summary>Gets or sets the roles assigned to the user.</summary>
    [JsonPropertyName("userRoles")]
    public IEnumerable<string> UserRoles { get; set; } = ["anonymous", "authenticated"];

    /// <summary>Gets or sets the claims collection from the identity token.</summary>
    [JsonPropertyName("claims")]
    public IEnumerable<ClientPrincipalClaim> Claims { get; set; } = [];

    /// <summary>
    /// Attempts to deserialise a <see cref="ClientPrincipal"/> from a base64-encoded header value.
    /// </summary>
    /// <param name="base64">The base64-encoded JSON string to deserialise.</param>
    /// <param name="principal">The deserialised <see cref="ClientPrincipal"/>, or <see langword="null"/> when unsuccessful.</param>
    /// <returns><see langword="true"/> if deserialisation succeeded; otherwise <see langword="false"/>.</returns>
    public static bool TryFromBase64(string? base64, out ClientPrincipal? principal)
    {
        principal = null;
        if (string.IsNullOrWhiteSpace(base64))
        {
            return false;
        }

        try
        {
            var bytes = Convert.FromBase64String(base64);
            principal = JsonSerializer.Deserialize<ClientPrincipal>(bytes, _serializerOptions);
            return principal is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Serialises the principal to a UTF-8 JSON byte array.
    /// </summary>
    /// <returns>The UTF-8 encoded JSON bytes of this principal.</returns>
    public byte[] ToJsonBytes() => JsonSerializer.SerializeToUtf8Bytes(this, _serializerOptions);

    /// <summary>
    /// Serialises the principal to a base64-encoded JSON string suitable for
    /// the <c>x-ms-client-principal</c> header.
    /// </summary>
    /// <returns>A base64-encoded JSON string representing this principal.</returns>
    public string ToBase64() => Convert.ToBase64String(ToJsonBytes());
}
