// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_value_outside_ascii;

/// <summary>
/// A carriage return, a line feed and a NUL are all below <c>U+0080</c>, so an encoder that asked only
/// "is this ASCII?" would pass them straight through and let a claim value write its own header. The
/// encoder emits nothing but RFC 8187 <c>attr-char</c> octets, which makes that structurally impossible
/// rather than merely checked for.
/// </summary>
public class and_it_has_control_characters : Specification
{
    const string Value = "victim\r\nx-ms-client-principal-id: attacker\0";

    string _transport;
    bool _decodeSucceeded;
    string _decoded;

    void Because()
    {
        _transport = HeaderValue.ToTransportValue(Value);
        _decodeSucceeded = HeaderValue.TryDecode(_transport, out _decoded);
    }

    [Fact] void should_require_an_extended_value() => HeaderValue.RequiresExtendedValue(Value).ShouldBeTrue();
    [Fact] void should_not_emit_a_carriage_return() => _transport.Contains('\r', StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_emit_a_line_feed() => _transport.Contains('\n', StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_emit_a_null() => _transport.Contains('\0', StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_send_only_printable_ascii() => _transport.Any(character => character is < ' ' or > '~').ShouldBeFalse();
    [Fact] void should_escape_the_line_break() => _transport.ShouldContain("%0D%0A");
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_original() => string.Equals(_decoded, Value, StringComparison.Ordinal).ShouldBeTrue();
}
