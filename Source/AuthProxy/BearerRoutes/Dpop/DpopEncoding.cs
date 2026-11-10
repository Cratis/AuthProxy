// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Canonical DPoP encodings and strict JSON parsing.</summary>
internal static class DpopEncoding
{
    /// <summary>Encodes bytes as canonical unpadded base64url.</summary>
    /// <param name="value">The bytes.</param>
    /// <returns>The encoding.</returns>
    internal static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Hashes a UTF-8 value with SHA-256.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The base64url digest.</returns>
    internal static string Hash(string value) => Encode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Decodes canonical unpadded base64url or throws.</summary>
    /// <param name="value">The encoding.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="FormatException">The encoding is non-canonical.</exception>
    internal static byte[] Decode(string value)
    {
        if (value.Length == 0 || value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_')) throw new FormatException();
        var decoded = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '='));
        if (Encode(decoded) != value) throw new FormatException();
        return decoded;
    }

    /// <summary>Checks the canonical SHA-256 thumbprint encoding.</summary>
    /// <param name="value">The thumbprint.</param>
    /// <returns>Whether it is canonical.</returns>
    internal static bool IsThumbprint(string value)
    {
        try
        {
            return value.Length == 43 && Decode(value).Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Compares bounded UTF-8 evidence without content-dependent equality.</summary>
    /// <param name="left">The presented evidence.</param>
    /// <param name="right">The expected evidence.</param>
    /// <returns>Whether the bytes match.</returns>
    internal static bool Equal(string left, string right) => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));

    /// <summary>Reads a bounded-depth JSON object without duplicate names.</summary>
    /// <param name="encoded">The base64url JSON.</param>
    /// <returns>The document; owned by the caller.</returns>
    /// <exception cref="JsonException">The document is not a unique-property JSON object.</exception>
    internal static JsonDocument Json(string encoded)
    {
        var bytes = Decode(encoded);
        if (bytes.Length > 2048) throw new JsonException();
        var document = JsonDocument.Parse(new UTF8Encoding(false, true).GetString(bytes), new JsonDocumentOptions { MaxDepth = 4 });
        if (document.RootElement.ValueKind != JsonValueKind.Object || !Unique(document.RootElement))
        {
            document.Dispose();
            throw new JsonException();
        }
        return document;
    }

    /// <summary>Checks recursive property-name uniqueness.</summary>
    /// <param name="element">The JSON value.</param>
    /// <returns>Whether every object has unique names.</returns>
    internal static bool Unique(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => UniqueObject(element),
        JsonValueKind.Array => element.EnumerateArray().All(Unique),
        _ => true,
    };

    /// <summary>Reads a string property without coercion.</summary>
    /// <param name="element">The object.</param>
    /// <param name="name">The property.</param>
    /// <returns>The string or null.</returns>
    internal static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    static bool UniqueObject(JsonElement element)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        return element.EnumerateObject().All(property => names.Add(property.Name) && Unique(property.Value));
    }
}
