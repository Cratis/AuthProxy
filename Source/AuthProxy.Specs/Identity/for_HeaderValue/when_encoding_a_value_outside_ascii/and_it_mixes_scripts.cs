// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_value_outside_ascii;

/// <summary>
/// The common real shape: an ASCII local part or company suffix next to a name that is not ASCII at all.
/// The safe run has to survive untouched inside the encoded value, and the rest has to come back exactly.
/// </summary>
public class and_it_mixes_scripts : Specification
{
    const string Value = "Ольга (Olga) 田中 <olga@example.com>";

    string _transport;
    bool _decodeSucceeded;
    string _decoded;

    void Because()
    {
        _transport = HeaderValue.ToTransportValue(Value);
        _decodeSucceeded = HeaderValue.TryDecode(_transport, out _decoded);
    }

    [Fact] void should_require_an_extended_value() => HeaderValue.RequiresExtendedValue(Value).ShouldBeTrue();
    [Fact] void should_announce_the_charset() => _transport.StartsWith(HeaderValue.ExtendedValuePrefix, StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_send_only_printable_ascii() => _transport.Any(character => character is < ' ' or > '~').ShouldBeFalse();
    [Fact] void should_keep_the_ascii_run_readable() => _transport.ShouldContain("Olga");
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_original() => string.Equals(_decoded, Value, StringComparison.Ordinal).ShouldBeTrue();
}
