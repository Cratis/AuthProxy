// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;

/// <summary>
/// Recognizes personal access tokens by their prefix and checks their shape. It never authenticates anyone: the
/// service behind the route is the verifier.
/// </summary>
/// <remarks>
/// The wire format is <c language="text">&lt;resource-key&gt;_pat_v1_&lt;64 lowercase hex&gt;_&lt;8 lowercase hex&gt;</c>, where
/// the last group is the first eight hex digits of the SHA-256 of everything before the final underscore. The
/// checksum detects transcription mistakes only, and it needs no secret, so the check is safe to make at the edge.
/// </remarks>
public static class PersonalAccessTokenClassifier
{
    const string Marker = "_pat_";
    const string VersionMarker = "pat_v1_";
    const string StagePrefix = "stage-";
    const int SecretLength = 64;
    const int ChecksumLength = 8;
    const int MaximumAppKeyLength = 48;

    static readonly SearchValues<char> _lowercaseKeyCharacters = SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789-");
    static readonly SearchValues<char> _lowercaseHexCharacters = SearchValues.Create("0123456789abcdef");

    /// <summary>
    /// Determines whether a value is in the personal access token namespace: it begins with an ASCII
    /// letter-or-digit resource-key prefix followed by <c language="text">_pat_</c>, matched case-insensitively, whatever
    /// follows.
    /// </summary>
    /// <param name="value">The credential value.</param>
    /// <returns><see langword="true"/> when the value belongs to the namespace; otherwise <see langword="false"/>.</returns>
    public static bool IsInNamespace(ReadOnlySpan<char> value)
    {
        var separator = value.IndexOf('_');
        if (separator <= 0
            || !IsAsciiLetterOrDigit(value[0])
            || !value[separator..].StartsWith(Marker, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach (var character in value[..separator])
        {
            if (!IsAsciiLetterOrDigit(character) && character != '-')
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Classifies a credential value.
    /// </summary>
    /// <param name="value">The credential value, exactly as presented.</param>
    /// <returns>The classification.</returns>
    public static PersonalAccessTokenShape Classify(string value)
    {
        if (!IsInNamespace(value.AsSpan().Trim()))
        {
            return new(PersonalAccessTokenKind.NotPersonalAccessToken);
        }

        return TryParse(value, out var resourceKey)
            ? new(PersonalAccessTokenKind.Canonical, resourceKey)
            : new(PersonalAccessTokenKind.Malformed);
    }

    /// <summary>
    /// Determines whether a value is a registered resource key: <c language="text">direct</c>, <c language="text">studio</c>
    /// or <c language="text">stage-&lt;app-key&gt;</c> with a 1 to 48 character lowercase letter, digit or internal hyphen app key.
    /// </summary>
    /// <param name="key">The candidate key.</param>
    /// <returns><see langword="true"/> when the key is acceptable; otherwise <see langword="false"/>.</returns>
    public static bool IsValidResourceKey(string? key)
    {
        if (string.Equals(key, "direct", StringComparison.Ordinal) || string.Equals(key, "studio", StringComparison.Ordinal))
        {
            return true;
        }

        if (key?.StartsWith(StagePrefix, StringComparison.Ordinal) != true)
        {
            return false;
        }

        var appKey = key.AsSpan(StagePrefix.Length);
        return appKey.Length is >= 1 and <= MaximumAppKeyLength
            && IsLowercaseLetterOrDigit(appKey[0])
            && IsLowercaseLetterOrDigit(appKey[^1])
            && !appKey.ContainsAnyExcept(_lowercaseKeyCharacters);
    }

    static bool TryParse(string value, out string resourceKey)
    {
        resourceKey = string.Empty;

        var separator = value.IndexOf('_', StringComparison.Ordinal);
        if (separator <= 0)
        {
            return false;
        }

        var key = value[..separator];
        var rest = value.AsSpan(separator + 1);
        if (!IsValidResourceKey(key)
            || !rest.StartsWith(VersionMarker, StringComparison.Ordinal)
            || rest.Length != VersionMarker.Length + SecretLength + 1 + ChecksumLength)
        {
            return false;
        }

        var secret = rest.Slice(VersionMarker.Length, SecretLength);
        var checksum = rest[^ChecksumLength..];
        if (rest[^(ChecksumLength + 1)] != '_'
            || secret.ContainsAnyExcept(_lowercaseHexCharacters)
            || checksum.ContainsAnyExcept(_lowercaseHexCharacters))
        {
            return false;
        }

        var body = value.AsSpan(0, value.Length - ChecksumLength - 1);
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.ASCII.GetBytes(body.ToString()), hash);
        var expected = Convert.ToHexStringLower(hash[..(ChecksumLength / 2)]);
        if (!checksum.SequenceEqual(expected))
        {
            return false;
        }

        resourceKey = key;
        return true;
    }

    static bool IsAsciiLetterOrDigit(char character) => char.IsAsciiLetterOrDigit(character);

    static bool IsLowercaseLetterOrDigit(char character) => character is (>= 'a' and <= 'z') or (>= '0' and <= '9');
}
