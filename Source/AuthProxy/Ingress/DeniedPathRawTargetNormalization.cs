// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Text;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Preserves original request-target segments while decoding their percent-encoded UTF-8 once.
/// </summary>
internal static class DeniedPathRawTargetNormalization
{
    static readonly UTF8Encoding _utf8 = new(false, true);

    /// <inheritdoc cref="DeniedPathNormalization.TryNormalizeRawTarget"/>
    internal static bool TryNormalize(string target, out string normalized)
    {
        normalized = string.Empty;
        if (!TryGetPath(target, out var path)) return false;
        if (!TryUnescape(path, out var decoded)) return false;
        return DeniedPathNormalization.TryNormalize(decoded, out normalized);
    }

    static bool TryGetPath(string target, out string path)
    {
        var delimiter = target.IndexOfAny(['?', '#']);
        if (delimiter >= 0) target = target[..delimiter];
        path = target;
        if (target.StartsWith('/')) return true;

        path = string.Empty;
        if (!target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return TryGetAbsolutePath(target, out path);
    }

    static bool TryGetAbsolutePath(string target, out string path)
    {
        path = string.Empty;
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri)) return false;
        if (string.IsNullOrEmpty(uri.Host)) return false;

        var authorityStart = target.IndexOf("://", StringComparison.Ordinal) + 3;
        var pathStart = target.IndexOf('/', authorityStart);
        var authorityEnd = pathStart < 0 ? target.Length : pathStart;
        if (target[authorityStart..authorityEnd].Contains('\\')) return false;

        // Uri validates the authority, but its normalized AbsolutePath would lose the original segments.
        path = pathStart < 0 ? "/" : target[pathStart..];
        return true;
    }

    static bool TryUnescape(string path, out string decoded)
    {
        decoded = string.Empty;
        try
        {
            var bytes = _utf8.GetBytes(path);
            if (!TryDecodeBytes(bytes, out var length)) return false;
            decoded = _utf8.GetString(bytes, 0, length);
            return !decoded.Any(char.IsControl);
        }
        catch (ArgumentException exception) when (exception is EncoderFallbackException or DecoderFallbackException)
        {
            // Invalid UTF-8 is ambiguous; never route it through the configured boundary.
            return false;
        }
    }

    static bool TryDecodeBytes(byte[] bytes, out int length)
    {
        length = 0;
        for (var index = 0; index < bytes.Length; index++)
        {
            var value = bytes[index];
            if (value == '%')
            {
                if (bytes.Length - index < 3) return false;
                if (!byte.TryParse(bytes.AsSpan(index + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value)) return false;
                index += 2;
            }

            bytes[length++] = value;
        }

        return true;
    }
}
