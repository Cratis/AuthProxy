// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Text;
using System.Text.Unicode;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Turns an identity value into something an HTTP header field can actually carry, and back again.
/// </summary>
/// <remarks>
/// A header field value is octets, and .NET refuses to put a character above <c>U+007F</c> on the wire:
/// the request never reaches the socket, it throws. A person named <c>Søren Wærstad</c> was therefore not
/// merely garbled downstream — the proxied request failed at the gateway and the identity-endpoint call
/// failed silently, so the application did not work for them at all. Names carrying arbitrary Unicode are
/// the normal case rather than the exotic one: three of the six claims <c>userDetails</c> is resolved from
/// are provider display names.
/// <para>
/// The encoding is the <see href="https://www.rfc-editor.org/rfc/rfc8187">RFC 8187</see> <c>ext-value</c> —
/// percent-encoded UTF-8 behind a self-describing <c>UTF-8''</c> prefix, which covers every code point
/// including the astral planes and needs no separate version header to announce itself.
/// </para>
/// <para>
/// It is applied <em>conditionally</em>. A value that a header field can already carry travels byte for
/// byte exactly as it always has, so an ASCII-only deployment sees no difference on the wire whatsoever.
/// Only a value that could not have been sent at all is encoded — this defines behavior where there was a
/// hard failure, it does not reinterpret a value that used to work.
/// </para>
/// <para>
/// Percent-encoding is deliberately conservative: only RFC 8187 <c>attr-char</c> octets survive verbatim,
/// which makes CR, LF and NUL structurally impossible to emit and header injection therefore impossible to
/// express through an identity value.
/// </para>
/// </remarks>
public static class HeaderValue
{
    /// <summary>
    /// The RFC 8187 charset-and-language prefix every encoded value carries.
    /// </summary>
    public const string ExtendedValuePrefix = "UTF-8''";

    const string AttributeCharacters = "!#$&+-.^_`|~";
    const string HexDigits = "0123456789ABCDEF";

    /// <summary>
    /// Determines whether a value can travel verbatim as an HTTP header field value.
    /// </summary>
    /// <param name="value">The value to inspect.</param>
    /// <returns><see langword="true"/> when every character is a printable US-ASCII one; otherwise <see langword="false"/>.</returns>
    public static bool IsSafeAscii(string value) =>
        value.All(character => character < 0x80 && !char.IsControl(character));

    /// <summary>
    /// Determines whether a value has to be carried as an RFC 8187 <c>ext-value</c>.
    /// </summary>
    /// <param name="value">The value to inspect.</param>
    /// <returns><see langword="true"/> when the value cannot travel verbatim; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// This is what decides whether the starred sibling header is emitted alongside the plain one, the same
    /// way <c>Content-Disposition</c> pairs <c>filename</c> with <c>filename*</c> (RFC 6266 §4.3).
    /// </remarks>
    public static bool RequiresExtendedValue(string value) => !IsSafeAscii(value);

    /// <summary>
    /// Converts a value to the form that goes on the wire.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>The value itself when it is already safe; otherwise its RFC 8187 <c>ext-value</c> form.</returns>
    public static string ToTransportValue(string value) => IsSafeAscii(value) ? value : Encode(value);

    /// <summary>
    /// Converts a transport value back to the value it was produced from.
    /// </summary>
    /// <param name="value">The value as it arrived on the header.</param>
    /// <param name="decoded">The original value, or <paramref name="value"/> unchanged when it could not be decoded.</param>
    /// <returns><see langword="true"/> when <paramref name="decoded"/> holds the original; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A value without the <c>UTF-8''</c> prefix was never encoded, so it decodes to itself — which makes
    /// this the exact inverse of <see cref="ToTransportValue"/> for every value that does not itself begin
    /// with that prefix. A consumer that wants an unambiguous answer reads the starred sibling header
    /// instead: its presence is what states that the plain header carries an <c>ext-value</c>.
    /// </remarks>
    public static bool TryDecode(string value, out string decoded)
    {
        if (!value.StartsWith(ExtendedValuePrefix, StringComparison.OrdinalIgnoreCase))
        {
            decoded = value;
            return true;
        }

        return TryDecodeExtendedValue(value.AsSpan(ExtendedValuePrefix.Length), value, out decoded);
    }

    static string Encode(string value)
    {
        var builder = new StringBuilder(ExtendedValuePrefix, ExtendedValuePrefix.Length + (value.Length * 4));

        foreach (var octet in Encoding.UTF8.GetBytes(value))
        {
            if (IsAttributeCharacter(octet))
            {
                builder.Append((char)octet);
            }
            else
            {
                builder.Append('%').Append(HexDigits[octet >> 4]).Append(HexDigits[octet & 0xF]);
            }
        }

        return builder.ToString();
    }

    static bool IsAttributeCharacter(byte octet) =>
        octet is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'0' and <= (byte)'9')
        || AttributeCharacters.Contains((char)octet, StringComparison.Ordinal);

    static bool TryDecodeExtendedValue(ReadOnlySpan<char> encoded, string original, out string decoded)
    {
        var octets = new byte[encoded.Length];
        var count = 0;

        for (var index = 0; index < encoded.Length; index++)
        {
            var character = encoded[index];

            if (character == '%')
            {
                if (index + 2 >= encoded.Length
                    || !TryParseHexDigit(encoded[index + 1], out var high)
                    || !TryParseHexDigit(encoded[index + 2], out var low))
                {
                    decoded = original;
                    return false;
                }

                octets[count++] = (byte)((high << 4) | low);
                index += 2;
            }
            else if (character < 0x80)
            {
                octets[count++] = (byte)character;
            }
            else
            {
                decoded = original;
                return false;
            }
        }

        var characters = new char[count];
        if (Utf8.ToUtf16(octets.AsSpan(0, count), characters, out _, out var written, replaceInvalidSequences: false) != OperationStatus.Done)
        {
            decoded = original;
            return false;
        }

        decoded = new string(characters, 0, written);
        return true;
    }

    static bool TryParseHexDigit(char character, out int value)
    {
        value = character switch
        {
            >= '0' and <= '9' => character - '0',
            >= 'a' and <= 'f' => character - 'a' + 10,
            >= 'A' and <= 'F' => character - 'A' + 10,
            _ => -1
        };

        return value >= 0;
    }
}
