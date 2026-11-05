// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;

namespace Cratis.AuthProxy;

/// <summary>
/// Removes the headers a client could use to tell a backend who it is or which tenant it is in.
/// </summary>
/// <remarks>
/// AuthProxy is the only thing that writes these, so a backend can trust them. A copy that survived from the
/// inbound request would make a backend believe whoever asked, which is why this is applied twice: to the
/// inbound request as soon as it is authenticated, and again to the outbound proxy request just before the
/// proxy's own values are written.
/// <para>
/// Identity headers are matched by the <see cref="Headers.PrincipalPrefix"/> rather than by name, so a header
/// the proxy never writes but a backend might read — <c language="text">x-ms-client-principal-idp</c>, or one added by a later
/// platform release — cannot be used to smuggle a claim. The tenant is stripped under every name it has ever
/// been forwarded in or that a downstream reads it from by default: <see cref="Headers.TenantId"/> and
/// <see cref="Headers.LegacyTenantId"/>. Only the tenant the proxy resolved itself is ever written back.
/// </para>
/// <para>
/// Every on-behalf header is matched by <see cref="Headers.OnBehalfPrefix"/> for the same reason: a caller must never
/// be able to name an actor, or present an assertion, that AuthProxy did not issue for this request.
/// </para>
/// <para>
/// Forwarded-identity context headers, including older draft names, are removed by exact name. Underscore
/// spellings are treated as hyphenated names because some backends map both spellings to the same variable.
/// Routing headers remain available for service selection.
/// </para>
/// </remarks>
static class SpoofableHeaders
{
    static readonly HashSet<string> _identityHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        Headers.ForwardedIdentitySignature, Headers.TenantId, Headers.LegacyTenantId, Headers.TokenClientId, Headers.TokenScope,
        "x-cratis-credential-kind", "x-cratis-credential-id", "x-cratis-issuer", "x-cratis-subject",
        "x-cratis-idp", "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act",
        "x-cratis-grant-id", "x-cratis-policy-epoch", "x-cratis-sender-binding", "x-cratis-forwarded-token-sha256",
        "x-cratis-assurance", "x-cratis-actor", "x-cratis-dpop-result"
    };

    /// <summary>
    /// Removes every spoofable header from an inbound request.
    /// </summary>
    /// <param name="headers">The inbound request headers.</param>
    public static void Strip(IHeaderDictionary headers)
    {
        foreach (var name in headers.Keys.Where(IsSpoofable).ToArray())
        {
            headers.Remove(name);
        }
    }

    /// <summary>
    /// Removes every spoofable header from a request about to be proxied.
    /// </summary>
    /// <param name="headers">The outbound request headers.</param>
    public static void Strip(HttpRequestHeaders headers)
    {
        foreach (var name in headers.NonValidated.Select(_ => _.Key).Where(IsSpoofable).ToArray())
        {
            headers.Remove(name);
        }
    }

    static bool IsSpoofable(string name)
    {
        var candidate = name.Replace('_', '-');
        return candidate.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase)
            || candidate.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase)
            || candidate.StartsWith(Headers.SignInCallbackPrefix, StringComparison.OrdinalIgnoreCase)
            || _identityHeaders.Contains(candidate);
    }
}
