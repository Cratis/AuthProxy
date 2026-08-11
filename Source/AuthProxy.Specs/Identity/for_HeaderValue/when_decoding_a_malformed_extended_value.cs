// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_HeaderValue;

/// <summary>
/// A consumer decoding a header it did not write has to be able to tell a value it understood from one it
/// did not — silently handing back a mangled name would be worse than refusing, because the caller would
/// have no way to know the identity it is acting on is wrong.
/// </summary>
public class when_decoding_a_malformed_extended_value : Specification
{
    bool _truncatedEscapeSucceeded;
    bool _nonHexEscapeSucceeded;
    bool _invalidUtf8Succeeded;
    string _truncatedEscape;

    void Because()
    {
        _truncatedEscapeSucceeded = HeaderValue.TryDecode("UTF-8''broken%C", out _truncatedEscape);
        _nonHexEscapeSucceeded = HeaderValue.TryDecode("UTF-8''broken%ZZ", out _);
        _invalidUtf8Succeeded = HeaderValue.TryDecode("UTF-8''%C3%28", out _);
    }

    [Fact] void should_refuse_a_truncated_escape() => _truncatedEscapeSucceeded.ShouldBeFalse();
    [Fact] void should_refuse_a_non_hexadecimal_escape() => _nonHexEscapeSucceeded.ShouldBeFalse();
    [Fact] void should_refuse_octets_that_are_not_utf8() => _invalidUtf8Succeeded.ShouldBeFalse();
    [Fact] void should_hand_back_the_value_it_was_given() => _truncatedEscape.ShouldEqual("UTF-8''broken%C");
}
