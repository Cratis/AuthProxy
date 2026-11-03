// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.WebUtilities;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Identifies the account a session belongs to, so the end of a credential link can be checked against the start.
/// </summary>
/// <remarks>
/// The value is computed from the session's provider and subject claims, never from the cookie instance, so it
/// stays the same while the cookie is renewed and changes as soon as a different account is signed in.
/// </remarks>
internal static class LinkSessionBinding
{
    static readonly string[] _claimTypes =
    [
        SessionClaims.ProviderScheme,
        CanonicalIdentityClaims.ProviderKey,
        CanonicalIdentityClaims.Issuer,
        CanonicalIdentityClaims.Subject,
        "iss",
        "sub",
        "oid",
        ClaimTypes.NameIdentifier,
    ];

    static readonly string[] _subjectClaimTypes =
    [
        CanonicalIdentityClaims.Subject,
        "sub",
        "oid",
        ClaimTypes.NameIdentifier,
    ];

    /// <summary>
    /// Creates the binding of the account a session principal represents.
    /// </summary>
    /// <param name="sessionPrincipal">The principal read from the session cookie.</param>
    /// <param name="binding">The binding, when the principal identifies an account.</param>
    /// <returns><see langword="true"/> when the principal carries a subject and a binding was created; otherwise <see langword="false"/>.</returns>
    public static bool TryCreate(ClaimsPrincipal? sessionPrincipal, out string binding)
    {
        binding = string.Empty;
        if (sessionPrincipal is null || !_subjectClaimTypes.Any(_ => HasValue(sessionPrincipal, _)))
        {
            return false;
        }

        var content = new StringBuilder();
        foreach (var type in _claimTypes)
        {
            foreach (var value in sessionPrincipal.FindAll(type).Select(_ => _.Value).Order(StringComparer.Ordinal))
            {
                content.Append(type).Append('\u001f').Append(value).Append('\u001e');
            }
        }

        binding = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToString())));
        return true;
    }

    static bool HasValue(ClaimsPrincipal principal, string type) =>
        principal.FindAll(type).Any(_ => !string.IsNullOrWhiteSpace(_.Value));
}
