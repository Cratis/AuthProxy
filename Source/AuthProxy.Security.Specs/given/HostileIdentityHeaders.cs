// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Text;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Caller-supplied identity headers and the oracle used at every recorded origin.
/// </summary>
public static class HostileIdentityHeaders
{
    /// <summary>The marker in caller-supplied values.</summary>
    public const string Marker = "caller-forged";

    /// <summary>Gets the caller-supplied principal.</summary>
    public static string ForgedPrincipal { get; } = Convert.ToBase64String(Encoding.UTF8.GetBytes(
        /*lang=json,strict*/ """{"identityProvider":"caller-forged","userId":"caller-forged","userDetails":"caller-forged","userRoles":["Administrator"]}"""));

    static readonly string[] _neverWritten =
    [
        "x-ms-client-principal-idp", "x-ms-client-principal-roles",
        "x-cratis-on-behalf-anything", "x-cratis-on-behalf-context",
        "x-cratis-sign-in-callback", "x-cratis-sign-in-callback-secret",
        "x-cratis-credential-kind", "x-cratis-credential-id", "x-cratis-issuer", "x-cratis-subject",
        "x-cratis-idp", "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act",
        "x-cratis-grant-id", "x-cratis-policy-epoch", "x-cratis-sender-binding", "x-cratis-forwarded-token-sha256",
        "x-cratis-assurance", "x-cratis-actor", "x-cratis-dpop-result"
    ];

    /// <summary>Gets every identity header supplied by the caller.</summary>
    public static IReadOnlyList<(string Name, string Value)> All { get; } = new (string, string)[]
    {
        (Headers.Principal, ForgedPrincipal),
        (Headers.PrincipalId, Marker), (Headers.PrincipalName, Marker), (Headers.PrincipalNameExtended, Marker),
        (Headers.TenantId, Marker), (Headers.LegacyTenantId, Marker),
        (Headers.TokenClientId, Marker), (Headers.TokenScope, Marker),
        ("x-cratis-on-behalf", Marker), ("x-cratis-on-behalf-actor", Marker), ("x-cratis-on-behalf-assertion", Marker),
        (Headers.ForwardedIdentitySignature, $"v1.active-1.0.{Marker}.{Marker}")
    }.Concat(_neverWritten.Select(name => (name, Marker))).ToArray();

    /// <summary>Gets the complete spelling matrix.</summary>
    public static IEnumerable<HostileHeaderVariant> Variants => Enum.GetValues<HostileHeaderVariant>();

    /// <summary>Applies a spelling to a fresh request.</summary>
    /// <param name="request">The request.</param>
    /// <param name="variant">The spelling.</param>
    public static void ApplyTo(HttpRequestMessage request, HostileHeaderVariant variant)
    {
        foreach (var (name, value) in All)
        {
            var spelling = Spelling(name, variant);
            request.Headers.TryAddWithoutValidation(spelling, value);
            if (variant is HostileHeaderVariant.Duplicated or HostileHeaderVariant.CaseDuplicated)
            {
                request.Headers.TryAddWithoutValidation(variant == HostileHeaderVariant.CaseDuplicated ? name.ToUpperInvariant() : name, $"{Marker}-second");
            }
        }
    }

    /// <summary>Finds caller-supplied identity headers in a wire observation.</summary>
    /// <param name="received">The observed headers.</param>
    /// <returns>The leaked names.</returns>
    public static IReadOnlyList<string> Leaks(IEnumerable<KeyValuePair<string, string[]>> received) => received
        .Where(header => header.Value.Any(value => value.Contains(Marker, StringComparison.Ordinal) || value == ForgedPrincipal)
            || (header.Key.Contains('_') && Protected(header.Key.Replace('_', '-')))
            || _neverWritten.Contains(header.Key, StringComparer.OrdinalIgnoreCase))
        .Select(header => header.Key).ToArray();

    /// <summary>Finds caller-supplied identity headers in a recording backend request.</summary>
    /// <param name="received">The observed headers.</param>
    /// <returns>The leaked names.</returns>
    public static IReadOnlyList<string> Leaks(IReadOnlyDictionary<string, string> received) =>
        Leaks(received.Select(header => new KeyValuePair<string, string[]>(header.Key, [header.Value])));

    static string Spelling(string name, HostileHeaderVariant variant) => variant switch
    {
        HostileHeaderVariant.Upper => name.ToUpperInvariant(),
        HostileHeaderVariant.Mixed => CultureInfo.InvariantCulture.TextInfo.ToTitleCase(name),
        HostileHeaderVariant.Underscored => name.Replace('-', '_'),
        _ => name
    };

    static bool Protected(string name) => All.Any(header => string.Equals(header.Name, name, StringComparison.OrdinalIgnoreCase))
        || name.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase)
        || name.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase)
        || name.StartsWith(Headers.SignInCallbackPrefix, StringComparison.OrdinalIgnoreCase);
}
