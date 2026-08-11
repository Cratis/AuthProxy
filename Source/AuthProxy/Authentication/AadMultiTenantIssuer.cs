// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates token issuers for the multi-tenant Microsoft Entra authorities (<c>common</c>,
/// <c>organizations</c>, <c>consumers</c>).
/// </summary>
/// <remarks>
/// A multi-tenant authority's discovery metadata declares its issuer as the literal template
/// <c>https://login.microsoftonline.com/{tenantid}/v2.0</c>, while every issued token carries the signing
/// tenant's real issuer — so the default comparison rejects every token (IDX10205), for organizational and
/// personal accounts alike. The fix Microsoft documents is a tenant-aware validator: substitute the token's
/// own <c>tid</c> claim into the template and require the issuer to match. The tenant is not an open
/// wildcard — the issuer must be exactly the Microsoft issuer for the tenant that the token itself claims,
/// with the signing key already validated against Microsoft's metadata before this runs.
/// </remarks>
public static class AadMultiTenantIssuer
{
    static readonly string[] _multiTenantSegments = ["common", "organizations", "consumers"];

    /// <summary>
    /// Checks whether an authority is one of the multi-tenant Microsoft Entra authorities that needs
    /// tenant-aware issuer validation.
    /// </summary>
    /// <param name="authority">The configured authority URL.</param>
    /// <returns><see langword="true"/> when the authority is a multi-tenant Microsoft authority; otherwise <see langword="false"/>.</returns>
    public static bool IsMultiTenantAuthority(string? authority) =>
        !string.IsNullOrWhiteSpace(authority)
        && Uri.TryCreate(authority, UriKind.Absolute, out var uri)
        && uri.Host.Equals("login.microsoftonline.com", StringComparison.OrdinalIgnoreCase)
        && _multiTenantSegments.Any(segment =>
            uri.AbsolutePath.Contains($"/{segment}/", StringComparison.OrdinalIgnoreCase)
            || uri.AbsolutePath.TrimEnd('/').EndsWith($"/{segment}", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Validates that a token's issuer is the Microsoft issuer for the tenant the token itself names in its
    /// <c>tid</c> claim. Assign to <see cref="TokenValidationParameters.IssuerValidator"/>.
    /// </summary>
    /// <param name="issuer">The issuer from the token being validated.</param>
    /// <param name="token">The token being validated.</param>
    /// <param name="validationParameters">The validation parameters in effect; required by the <see cref="IssuerValidator"/> delegate contract.</param>
    /// <returns>The validated issuer.</returns>
    /// <exception cref="SecurityTokenInvalidIssuerException">
    /// Thrown when the token carries no tenant or the issuer is not that tenant's Microsoft issuer. The
    /// built-in exception type is required here — it is the contract
    /// <see cref="TokenValidationParameters.IssuerValidator"/> expects for a rejected issuer.
    /// </exception>
    public static string Validate(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
    {
        ArgumentNullException.ThrowIfNull(validationParameters);

        var tenantId = token is JsonWebToken jsonWebToken && jsonWebToken.TryGetPayloadValue<string>("tid", out var tid)
            ? tid
            : null;

        if (!string.IsNullOrWhiteSpace(tenantId)
            && (issuer.Equals($"https://login.microsoftonline.com/{tenantId}/v2.0", StringComparison.OrdinalIgnoreCase)
                || issuer.Equals($"https://sts.windows.net/{tenantId}/", StringComparison.OrdinalIgnoreCase)))
        {
            return issuer;
        }

        throw new SecurityTokenInvalidIssuerException(
            $"Issuer '{issuer}' is not the Microsoft issuer for the tenant the token names ('{tenantId ?? "<none>"}').")
        {
            InvalidIssuer = issuer,
        };
    }
}
