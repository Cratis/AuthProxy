// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_value_that_already_looks_encoded;

/// <summary>
/// The attack the prefix rule exists for. Setting a provider display name to
/// <c>UTF-8''victim%0D%0AX-Admin:%20true</c> is printable US-ASCII throughout, so it used to travel byte for
/// byte with no sibling — and a backend following the published decode snippet, which branched on the
/// prefix, decoded it and obtained a carriage return, a line feed and a header of the caller's choosing.
/// CR and LF were structurally impossible to <em>emit</em> and perfectly possible to <em>reconstruct</em>.
/// <para>
/// Two things close it, and both are asserted here: the value is encoded rather than forwarded, so what
/// travels no longer looks like an ext-value it is not; and decoding it once — which is what the corrected
/// guidance says to do, gated on the sibling header rather than on the prefix — yields the literal name back,
/// not a header separator.
/// </para>
/// </summary>
public class and_it_hides_a_line_break_behind_the_prefix : Specification
{
    const string Value = "UTF-8''victim%0D%0AX-Admin:%20true";

    string _transport;
    bool _decodeSucceeded;
    string _decoded;

    void Because()
    {
        _transport = HeaderValue.ToTransportValue(Value);
        _decodeSucceeded = HeaderValue.TryDecode(_transport, out _decoded);
    }

    [Fact] void should_require_an_extended_value() => HeaderValue.RequiresExtendedValue(Value).ShouldBeTrue();
    [Fact] void should_not_forward_it_verbatim() => _transport.ShouldNotEqual(Value);
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_exact_original() => string.Equals(_decoded, Value, StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_not_yield_a_carriage_return_at_the_consumer() => _decoded.Contains('\r', StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_yield_a_line_feed_at_the_consumer() => _decoded.Contains('\n', StringComparison.Ordinal).ShouldBeFalse();
}
