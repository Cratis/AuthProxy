// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPathPolicy;

/// <summary>
/// An entry that does not name a path prefix at all is refused, and refused with the reason that says
/// which failure it was.
/// <para>
/// The entries that resolve to the application root are the ones that matter most:
/// <c>PathString.StartsWithSegments(string.Empty)</c> is true for every request, so a blank value — an
/// environment variable set but never given one, a trailing index in a configuration array — would turn an
/// entire service anonymous, silently and globally. That is the worst outcome this feature can produce, so
/// every spelling of it is pinned here rather than left to review.
/// </para>
/// </summary>
public class when_an_entry_cannot_name_a_prefix : Specification
{
    static AnonymousPathRejection Evaluate(string? candidate) => AnonymousPathPolicy.Evaluate(candidate, out _);

    [Fact] void should_refuse_a_null_entry() => Evaluate(null).ShouldEqual(AnonymousPathRejection.Empty);
    [Fact] void should_refuse_an_empty_entry() => Evaluate(string.Empty).ShouldEqual(AnonymousPathRejection.Empty);
    [Fact] void should_refuse_a_whitespace_entry() => Evaluate("   ").ShouldEqual(AnonymousPathRejection.Empty);
    [Fact] void should_refuse_the_root() => Evaluate("/").ShouldEqual(AnonymousPathRejection.Root);
    [Fact] void should_refuse_repeated_separators_that_trim_to_the_root() => Evaluate("///").ShouldEqual(AnonymousPathRejection.Root);
    [Fact] void should_refuse_a_root_with_surrounding_whitespace() => Evaluate("  /  ").ShouldEqual(AnonymousPathRejection.Root);
    [Fact] void should_refuse_an_unrooted_entry() => Evaluate("portal").ShouldEqual(AnonymousPathRejection.NotRooted);
    [Fact] void should_refuse_a_protocol_relative_entry() => Evaluate("//evil.test/portal").ShouldEqual(AnonymousPathRejection.EmptySegment);
    [Fact] void should_refuse_a_repeated_inner_separator() => Evaluate("/double//segment").ShouldEqual(AnonymousPathRejection.EmptySegment);

    [Fact] void should_accept_a_trimmed_entry() => Evaluate("  /portal/  ").ShouldEqual(AnonymousPathRejection.None);

    [Fact] void should_normalize_a_trimmed_entry_to_its_prefix()
    {
        AnonymousPathPolicy.Evaluate("  /portal/  ", out var prefix);
        prefix.ShouldEqual("/portal");
    }

    [Fact] void should_yield_no_prefix_for_a_refused_entry()
    {
        AnonymousPathPolicy.Evaluate("/route{parameter}", out var prefix);
        prefix.ShouldBeEmpty();
    }
}
