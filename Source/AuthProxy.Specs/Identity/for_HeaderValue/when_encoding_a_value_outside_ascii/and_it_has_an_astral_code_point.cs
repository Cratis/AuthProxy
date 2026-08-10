// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_value_outside_ascii;

/// <summary>
/// A code point above the basic multilingual plane, which is a surrogate pair in the .NET string and four
/// octets in UTF-8. Providers happily hand out display names containing emoji, so a scheme that only
/// reaches U+FFFF would still fail for real people.
/// </summary>
public class and_it_has_an_astral_code_point : Specification
{
    const string Value = "Ada 🐝";

    string _transport;
    bool _decodeSucceeded;
    string _decoded;

    void Because()
    {
        _transport = HeaderValue.ToTransportValue(Value);
        _decodeSucceeded = HeaderValue.TryDecode(_transport, out _decoded);
    }

    [Fact] void should_require_an_extended_value() => HeaderValue.RequiresExtendedValue(Value).ShouldBeTrue();
    [Fact] void should_encode_the_surrogate_pair_as_four_octets() => _transport.ShouldEqual("UTF-8''Ada%20%F0%9F%90%9D");
    [Fact] void should_send_only_printable_ascii() => _transport.Any(character => character is < ' ' or > '~').ShouldBeFalse();
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_original() => string.Equals(_decoded, Value, StringComparison.Ordinal).ShouldBeTrue();
}
