// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue.when_encoding_a_safe_value;

/// <summary>
/// The ordinary case, and the one an existing deployment has to keep seeing unchanged: a name a header
/// field can already carry goes on the wire byte for byte, with no sibling header announcing anything.
/// </summary>
public class and_it_is_an_email_address : Specification
{
    const string Value = "user@example.com";

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
    [Fact] void should_consider_the_value_safe() => HeaderValue.IsSafeAscii(Value).ShouldBeTrue();
    [Fact] void should_decode_it() => _decodeSucceeded.ShouldBeTrue();
    [Fact] void should_round_trip_to_the_original() => _decoded.ShouldEqual(Value);
}
