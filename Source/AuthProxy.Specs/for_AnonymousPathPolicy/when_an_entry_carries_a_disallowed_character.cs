// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPathPolicy;

/// <summary>
/// The permitted characters are an allow-list — RFC 3986 unreserved plus the separator — so a character
/// that carries meaning to either matcher is refused by construction rather than by having been
/// anticipated.
/// <para>
/// The failure this prevents is a prefix that means one thing to the middlewares, which match a literal
/// with <see cref="PathString.StartsWithSegments(PathString)"/>, and another to the router, which matches
/// an ASP.NET route template built from the same string. <c>/a{x}</c> is the sharpest example: as a
/// template it is a route <em>parameter</em>, so the router would serve <c>/aANYTHING/…</c> anonymously
/// while the middlewares matched only <c>/a{x}</c> — an unauthenticated surface far wider than anything
/// declared.
/// </para>
/// </summary>
public class when_an_entry_carries_a_disallowed_character : Specification
{
    static AnonymousPathRejection Evaluate(string candidate) => AnonymousPathPolicy.Evaluate(candidate, out _);

    [Fact] void should_refuse_a_route_parameter() => Evaluate("/route{parameter}").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_catch_all() => Evaluate("/catch/{**all}").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_wildcard() => Evaluate("/star*").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_query_string() => Evaluate("/query?token=1").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_fragment() => Evaluate("/page#section").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_path_parameter() => Evaluate("/public;/admin").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_an_authority_separator() => Evaluate("/public@evil.test").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_scheme_separator() => Evaluate("/http://evil.test").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_an_inner_space() => Evaluate("/with space").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_carriage_return() => Evaluate("/public\r\nSet-Cookie: a=b").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_tab() => Evaluate("/public\tadmin").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_raw_null_byte() => Evaluate("/public\0").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_non_ascii_character() => Evaluate("/públic").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_homoglyph() => Evaluate("/publiс").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);
    [Fact] void should_refuse_a_zero_width_joiner() => Evaluate("/pub‍lic").ShouldEqual(AnonymousPathRejection.DisallowedCharacter);

    [Fact] void should_keep_letters_digits_and_unreserved_punctuation() =>
        Evaluate("/api/reports-v2/public_data~1").ShouldEqual(AnonymousPathRejection.None);
}
