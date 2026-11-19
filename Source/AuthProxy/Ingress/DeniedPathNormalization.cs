// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Normalizes an origin-form raw request target without relying on the server's decoded Path.
/// </summary>
public static class DeniedPathNormalization
{
    static readonly UTF8Encoding _strictUtf8 = new(false, true);

    /// <summary>
    /// Decodes once, merges slashes and resolves dot segments; refuses ambiguous representations.
    /// </summary>
    /// <param name="target">The raw request target, including any query string.</param>
    /// <param name="path">The normalized path, without a trailing slash except at the root.</param>
    /// <returns>Whether the target has an unambiguous path.</returns>
    public static bool TryNormalize(string? target, out string path)
    {
        path = string.Empty;
        if (string.IsNullOrEmpty(target) || !target.StartsWith('/')) return false;

        var rawPath = target.Split('?', 2)[0];
        if (!TryDecode(rawPath, out var decoded) || decoded.Any(IsAmbiguous)) return false;

        var segments = new List<string>();
        foreach (var segment in decoded.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!ApplySegment(segments, segment)) return false;
        }

        path = $"/{string.Join('/', segments)}";
        return true;
    }

    static bool ApplySegment(List<string> segments, string segment)
    {
        if (segment == ".") return true;
        if (segment != "..")
        {
            segments.Add(segment);
            return true;
        }

        if (segments.Count == 0) return false;
        segments.RemoveAt(segments.Count - 1);
        return true;
    }

    static bool IsAmbiguous(char character) =>
        char.IsControl(character) || char.IsWhiteSpace(character) || character is '\\' or ';' or '#' or '?' or '%';

    static bool TryDecode(string rawPath, out string decoded)
    {
        decoded = string.Empty;
        var bytes = new List<byte>(rawPath.Length);
        for (var index = 0; index < rawPath.Length; index++)
        {
            var character = rawPath[index];
            if (character > 127) return false;
            if (character != '%')
            {
                bytes.Add((byte)character);
                continue;
            }

            if (!TryReadEscape(rawPath, index, out var value)) return false;
            bytes.Add(value);
            index += 2;
        }

        return TryDecodeUtf8(bytes, out decoded);
    }

    static bool TryReadEscape(string path, int index, out byte value)
    {
        value = 0;
        if (index + 2 >= path.Length) return false;
        if (!Uri.IsHexDigit(path[index + 1]) || !Uri.IsHexDigit(path[index + 2])) return false;
        value = (byte)((Uri.FromHex(path[index + 1]) << 4) | Uri.FromHex(path[index + 2]));
        return value is not (0x2f or 0x5c);
    }

    static bool TryDecodeUtf8(List<byte> bytes, out string decoded)
    {
        decoded = string.Empty;
        try
        {
            decoded = _strictUtf8.GetString(bytes.ToArray());
            return true;
        }
        catch (DecoderFallbackException)
        {
            // Invalid UTF-8 cannot be compared safely with downstream path interpretations.
            return false;
        }
    }
}
