// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Seals resource-domain nonces using the approved Data Protection encoding.</summary>
/// <param name="protection">The fleet-shared key ring.</param>
/// <param name="clock">The checked deployment clock.</param>
internal sealed class DpopNonce(IDataProtectionProvider protection, TimeProvider clock)
{
    readonly IDataProtector _protector = protection.CreateProtector("Cratis.AuthProxy.Dpop.Nonce.v1");

    /// <summary>Creates a nonce after store health has been checked.</summary>
    /// <param name="route">The trusted public origin.</param>
    /// <param name="jkt">The validated key.</param>
    /// <returns>The opaque nonce.</returns>
    internal string Create(ResolvedBearerRoute route, string jkt) => _protector.Protect(JsonSerializer.Serialize(
        new Payload(1, "resource", Origin(route), jkt, clock.GetUtcNow().ToUnixTimeSeconds(), DpopEncoding.Encode(RandomNumberGenerator.GetBytes(16)))));

    /// <summary>Checks nonce integrity, domain, origin, key and the exclusive 330-second lifetime.</summary>
    /// <param name="value">The presented nonce.</param>
    /// <param name="route">The route.</param>
    /// <param name="jkt">The verified key.</param>
    /// <returns>Whether the nonce is valid.</returns>
    internal bool Valid(string? value, ResolvedBearerRoute route, string jkt)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 1024) return false;
        try
        {
            var payload = JsonSerializer.Deserialize<Payload>(_protector.Unprotect(value));
            var now = clock.GetUtcNow().ToUnixTimeSeconds();
            return payload?.Domain == "resource" && payload.Version == 1
                && DpopEncoding.Equal(payload.Jkt, jkt) && DpopEncoding.Equal(payload.Origin, Origin(route))
                && payload.Issued <= now + 30 && payload.Issued > now - 330;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    static string Origin(ResolvedBearerRoute route) => DpopTargetUri.TryOrigin(route.Route.Dpop!.PublicOrigin, out var origin) ? origin : string.Empty;
    sealed record Payload(int Version, string Domain, string Origin, string Jkt, long Issued, string Random);
}
