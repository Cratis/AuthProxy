// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_safe_value;

/// <summary>
/// Percent signs, quotes, apostrophes, commas, semicolons and spaces are all characters the RFC 8187
/// encoder would escape — and all characters an existing ASCII name is allowed to contain. Encoding
/// unconditionally would silently rewrite every one of those deployments, which is precisely why the
/// encoding is conditional.
/// </summary>
public class and_it_has_punctuation_the_encoder_would_escape : Specification
{
    const string Value = """O'Brien, "100% Sure"; a b""";

    string _transport;
    bool _requiresExtendedValue;
    bool _decodeSucceeded;
    string _decoded;

    void Because()
    {
        _transport = HeaderValue.ToTransportValue(Value);
        _requiresExtendedValue = HeaderValue.RequiresExtendedValue(Value);
        _decodeSucceeded = HeaderValue.TryDecode(_transport, out _decoded);
    }

    [Fact] void should_send_the_value_byte_identically() => _transport.ShouldEqual(Value);
    [Fact] void should_not_require_an_extended_value() => _requiresExtendedValue.ShouldBeFalse();
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_original() => _decoded.ShouldEqual(Value);
}
