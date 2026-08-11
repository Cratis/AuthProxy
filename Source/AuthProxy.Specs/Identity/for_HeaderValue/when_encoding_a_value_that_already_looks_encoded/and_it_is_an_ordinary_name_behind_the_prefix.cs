// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_value_that_already_looks_encoded;

/// <summary>
/// A display name is whatever the person typed, and nothing stops them typing the charset prefix. Every
/// character of it is printable US-ASCII, so a rule that asked only "is this ASCII?" sent it verbatim and
/// emitted no sibling — leaving the plain header carrying something indistinguishable from an
/// <c>ext-value</c> and nothing anywhere saying which it was. Encoding it makes the two answerable
/// separately: the sibling says it is encoded, and decoding gives back exactly what was typed.
/// </summary>
public class and_it_is_an_ordinary_name_behind_the_prefix : Specification
{
    const string Value = "UTF-8''Jane Doe";

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

    [Fact] void should_require_an_extended_value() => _requiresExtendedValue.ShouldBeTrue();
    [Fact] void should_not_send_it_verbatim() => _transport.ShouldNotEqual(Value);
    [Fact] void should_send_only_printable_ascii() => _transport.Any(character => character is < ' ' or > '~').ShouldBeFalse();
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_exact_original() => string.Equals(_decoded, Value, StringComparison.Ordinal).ShouldBeTrue();
}
