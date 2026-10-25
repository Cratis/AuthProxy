// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Reads only unique public RSA signing keys from an invitation-token JWKS.
/// </summary>
internal static class InvitationTokenKeySet
{
    static readonly string[] _privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    /// <summary>
    /// Parses a bounded public key set, skipping keys that do not qualify for invitation signing.
    /// </summary>
    /// <param name="json">The JWKS bytes.</param>
    /// <param name="keys">The qualifying keys indexed by their unique identifiers.</param>
    /// <param name="failure">A rejection reason without key material.</param>
    /// <returns>Whether the whole set is safe to accept, even if it has no qualifying keys.</returns>
    internal static bool TryParse(ReadOnlySpan<byte> json, out IReadOnlyDictionary<string, SecurityKey> keys, out string failure)
    {
        keys = new Dictionary<string, SecurityKey>(StringComparer.Ordinal);
        failure = "Invalid invitation-token key set.";
        try
        {
            using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 8, AllowDuplicateProperties = false });
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !HasKeysArray(document.RootElement, out var entries))
            {
                return false;
            }
            if (entries.GetArrayLength() > InvitationTokenKeys.MaximumKeys || entries.EnumerateArray().Any(HasPrivateMaterial))
            {
                failure = "Key set exceeds the key limit or contains private key material.";
                return false;
            }

            keys = PublicKeys(entries);
            failure = string.Empty;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    static bool HasPrivateMaterial(JsonElement entry) =>
        entry.ValueKind == JsonValueKind.Object && _privateMembers.Any(name => entry.TryGetProperty(name, out _));

    static bool HasKeysArray(JsonElement root, out JsonElement entries) =>
        root.TryGetProperty("keys", out entries) && entries.ValueKind == JsonValueKind.Array;

    static Dictionary<string, SecurityKey> PublicKeys(JsonElement entries)
    {
        var groups = entries.EnumerateArray().Where(entry => entry.ValueKind == JsonValueKind.Object)
            .GroupBy(entry => Text(entry, "kid"), StringComparer.Ordinal)
            .Where(group => !string.IsNullOrEmpty(group.Key) && group.Count() == 1);
        var keys = new Dictionary<string, SecurityKey>(StringComparer.Ordinal);
        foreach (var group in groups)
        {
            if (TryCreateKey(group.Single(), group.Key!, out var key))
            {
                keys.Add(group.Key!, key);
            }
        }
        return keys;
    }

    static bool TryCreateKey(JsonElement entry, string kid, out SecurityKey key)
    {
        key = null!;
        if (!QualifiesForSigning(entry))
        {
            return false;
        }

        try
        {
            var parameters = new RSAParameters { Modulus = Decode(Text(entry, "n")), Exponent = Decode(Text(entry, "e")) };
            using var rsa = RSA.Create();
            rsa.ImportParameters(parameters);
            if (rsa.KeySize < 2048)
            {
                return false;
            }
            key = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = kid };
            return true;
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    static bool QualifiesForSigning(JsonElement entry) =>
        string.Equals(Text(entry, "kty"), "RSA", StringComparison.Ordinal) && OptionalMatches(entry, "use", "sig") && OptionalMatches(entry, "alg", "RS256");

    static bool OptionalMatches(JsonElement entry, string name, string expected) =>
        !entry.TryGetProperty(name, out _) || string.Equals(Text(entry, name), expected, StringComparison.Ordinal);

    static string? Text(JsonElement entry, string name) =>
        entry.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    static byte[] Decode(string? value)
    {
        if (string.IsNullOrEmpty(value) || !value.All(IsBase64UrlCharacter))
        {
            throw new FormatException("Invalid base64url public parameter.");
        }
        return Base64UrlEncoder.DecodeBytes(value);
    }

    static bool IsBase64UrlCharacter(char character) => char.IsAsciiLetterOrDigit(character) || character is '-' or '_';
}
