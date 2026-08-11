// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_value_outside_ascii;

/// <summary>
/// The name from the report. Nothing about it is unusual anywhere the product is sold, and before this it
/// could not be forwarded at all.
/// </summary>
public class and_it_is_accented_latin : Specification
{
    const string Value = "Søren Wærstad";

    string _transport;
    bool _decodeSucceeded;
    string _decoded;

    void Because()
    {
        _transport = HeaderValue.ToTransportValue(Value);
        _decodeSucceeded = HeaderValue.TryDecode(_transport, out _decoded);
    }

    [Fact] void should_require_an_extended_value() => HeaderValue.RequiresExtendedValue(Value).ShouldBeTrue();
    [Fact] void should_encode_it_as_an_rfc_8187_extended_value() => _transport.ShouldEqual("UTF-8''S%C3%B8ren%20W%C3%A6rstad");
    [Fact] void should_send_only_printable_ascii() => _transport.Any(character => character is < ' ' or > '~').ShouldBeFalse();
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_original() => string.Equals(_decoded, Value, StringComparison.Ordinal).ShouldBeTrue();
}
