// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPathPolicy;

/// <summary>
/// A declared prefix must mean exactly what it spells. Every traversal form is refused rather than
/// resolved, so a prefix can never open a path the operator did not name.
/// <para>
/// Resolving would be the more forgiving choice and the wrong one: <c>/public/../admin</c> reads as scoped
/// to <c>/public</c> while meaning <c>/admin</c>, so accepting it as <c>/admin</c> would hand an
/// unauthenticated caller a surface nobody typed. The encoded spellings — <c>%2e%2e%2f</c>, <c>%2f</c>,
/// <c>%00</c> — are refused one step earlier, by the character allow-list, which is why they are pinned
/// here alongside the literal form: they are the same attack and must not survive by taking a different
/// route through the check.
/// </para>
/// </summary>
public class when_an_entry_attempts_traversal : Specification
{
    static AnonymousPathRejection Evaluate(string candidate) => AnonymousPathPolicy.Evaluate(candidate, out _);

    [Fact] void should_refuse_a_parent_segment() => Evaluate("/public/../admin").ShouldEqual(AnonymousPathRejection.DotSegment);
    [Fact] void should_refuse_a_trailing_parent_segment() => Evaluate("/public/..").ShouldEqual(AnonymousPathRejection.DotSegment);
    [Fact] void should_refuse_a_leading_parent_segment() => Evaluate("/../admin").ShouldEqual(AnonymousPathRejection.DotSegment);
    [Fact] void should_refuse_a_current_segment() => Evaluate("/public/./admin").ShouldEqual(AnonymousPathRejection.DotSegment);
    [Fact] void should_refuse_a_bare_current_segment() => Evaluate("/.").ShouldEqual(AnonymousPathRejection.DotSegment);
    [Fact] void should_refuse_stacked_parent_segments() => Evaluate("/a/../../..").ShouldEqual(AnonymousPathRejection.DotSegment);

    [Fact] void should_refuse_an_encoded_parent_segment() => Evaluate("/public/%2e%2e/admin").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_an_encoded_separator() => Evaluate("/public%2fadmin").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_double_encoded_parent_segment() => Evaluate("/public/%252e%252e/admin").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_an_encoded_null_byte() => Evaluate("/public%00.png").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_backslash_separator() => Evaluate("/public\\..\\admin").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_an_overlong_encoded_separator() => Evaluate("/public%c0%afadmin").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);

    [Fact] void should_keep_a_dot_inside_a_segment() => Evaluate("/.well-known/acme-challenge").ShouldEqual(AnonymousPathRejection.None);
    [Fact] void should_keep_a_file_extension() => Evaluate("/public/health.json").ShouldEqual(AnonymousPathRejection.None);
}
