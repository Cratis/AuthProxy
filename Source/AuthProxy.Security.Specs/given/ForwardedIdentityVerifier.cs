// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Independent host-side v1 verifier, adapted from Cratis/Arc@a8599847b0cf19a4dd5cb1a81f53dd5d2203f559,
/// Source/DotNET/Specs.Shared/ForwardedIdentityForSpecs.cs and Arc.Core/Identity/ForwardedIdentityCanonicalization.cs.
/// Does not call AuthProxy's canonicalizer or signer.
/// </summary>
public static class ForwardedIdentityVerifier
{
    /// <summary>Verifies the observed method, raw path and covered values against one receiver's key.</summary>
    /// <param name="observed">The wire observation.</param>
    /// <param name="audience">The receiving audience.</param>
    /// <param name="keyId">The receiving key identifier.</param>
    /// <param name="secret">The receiving shared key.</param>
    /// <returns>Whether the bounded v1 proof verifies.</returns>
    public static bool Verify(ForwardedIdentityObservation observed, string audience, string keyId, byte[] secret)
    {
        if (!observed.Headers.TryGetValue("x-cratis-forwarded-identity-signature", out var signatures) || signatures.Length != 1) return false;
        var parts = signatures[0].Split('.');
        if (parts.Length != 5 || parts[0] != "v1" || parts[1] != keyId || parts[3].Length != 43 || parts[4].Length != 43 ||
            !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp) ||
            Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp) > 60)
        {
            return false;
        }

        var path = observed.RawTarget.Split('?', 2)[0].ToCharArray();
        if (path.Length == 0 || path[0] != '/') return false;
        for (var index = 0; index < path.Length; index++)
        {
            if (path[index] != '%') continue;
            if (index + 2 >= path.Length || !Uri.IsHexDigit(path[index + 1]) || !Uri.IsHexDigit(path[index + 2])) return false;
            path[++index] = char.ToUpperInvariant(path[index]);
            path[++index] = char.ToUpperInvariant(path[index]);
        }
        var covered = observed.Headers.Where(header => IsCovered(header.Key)).OrderBy(header => header.Key.ToLowerInvariant(), StringComparer.Ordinal).ToArray();
        if (covered.Length > 64 || covered.Any(header => header.Value.Length != 1)) return false;
        if (new[] { "x-ms-client-principal", "x-ms-client-principal-id", "x-ms-client-principal-name" }.Any(name => !observed.Headers.TryGetValue(name, out var values) || values.Length != 1 || string.IsNullOrWhiteSpace(values[0]))) return false;

        var canonical = new StringBuilder("Cratis.AuthProxy.ForwardedIdentity.v1\n");
        foreach (var value in new[] { audience, keyId, parts[2], parts[3], observed.Method, new string(path), covered.Length.ToString(CultureInfo.InvariantCulture) }) canonical.Append(Frame(value));
        foreach (var header in covered)
        {
            var value = header.Value[0].Trim(' ', '\t');
            if (value.Any(character => character is < ' ' or >= (char)127)) return false;
            canonical.Append(Frame(header.Key.ToLowerInvariant())).Append(Frame(value));
        }
        var bytes = Encoding.UTF8.GetBytes(canonical.ToString());
        if (bytes.Length > 32768) return false;
        var expected = Convert.ToBase64String(HMACSHA256.HashData(secret, bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(parts[4]));
    }

    static string Frame(string value) => $"{Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture)}:{value}\n";

    static bool IsCovered(string name) =>
        name.StartsWith("x-ms-client-principal", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("x-cratis-on-behalf", StringComparison.OrdinalIgnoreCase) ||
        new[] { "x-cratis-token-client-id", "x-cratis-token-scope", "x-cratis-tenant-id", "tenant-id", "x-cratis-microservice", "service-id" }.Contains(name, StringComparer.OrdinalIgnoreCase);
}
