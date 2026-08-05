// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_RelativeRedirect;

/// <summary>
/// The single check that decides whether a caller-supplied redirect target can navigate off-site.
/// <para>
/// Four endpoints hand the browser a target the caller chose — the login <c>returnUrl</c>, the link
/// <c>returnUrl</c>, tenant selection's <c>returnUrl</c>, and logout's <c>redirect</c> — and each used to
/// carry its own version of this check. They disagreed, which is the whole reason the check moved here: one
/// accepted <c>//evil.test</c> outright, and the two that rejected it still accepted <c>/\evil.test</c>.
/// </para>
/// <para>
/// What every disagreement had in common was treating a leading <c>/</c> as proof of same-site. It is not,
/// because the browser decides what a <c>Location</c> means. <c>//host</c> is protocol-relative;
/// <c>/\host</c> is the same URL to every major browser, which normalize a backslash to a slash in the
/// authority position; and a slash followed by a tab, carriage return or newline is also the same URL,
/// because browsers strip those characters before parsing — so the string checked here and the URL actually
/// fetched would be different strings.
/// </para>
/// </summary>
public class when_deciding_whether_a_target_is_same_site : Specification
{
    [Fact] void should_reject_nothing_at_all() => RelativeRedirect.IsSameSiteRelative(null).ShouldBeFalse();
    [Fact] void should_reject_an_empty_target() => RelativeRedirect.IsSameSiteRelative(string.Empty).ShouldBeFalse();
    [Fact] void should_reject_an_unrooted_target() => RelativeRedirect.IsSameSiteRelative("dashboard").ShouldBeFalse();

    [Fact] void should_reject_a_protocol_relative_target() => RelativeRedirect.IsSameSiteRelative("//evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_protocol_relative_target_with_a_path() => RelativeRedirect.IsSameSiteRelative("//evil.test/phish").ShouldBeFalse();
    [Fact] void should_reject_three_leading_slashes() => RelativeRedirect.IsSameSiteRelative("///evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_protocol_relative_target_carrying_userinfo() => RelativeRedirect.IsSameSiteRelative("//user:pass@evil.test").ShouldBeFalse();

    [Fact] void should_reject_a_backslash_authority() => RelativeRedirect.IsSameSiteRelative("/\\evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_mixed_slash_authority() => RelativeRedirect.IsSameSiteRelative("/\\/evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_double_backslash_authority() => RelativeRedirect.IsSameSiteRelative("/\\\\evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_leading_double_backslash() => RelativeRedirect.IsSameSiteRelative("\\\\evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_backslash_anywhere() => RelativeRedirect.IsSameSiteRelative("/dashboard\\evil.test").ShouldBeFalse();

    [Fact] void should_reject_a_stripped_tab() => RelativeRedirect.IsSameSiteRelative("/\t/evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_stripped_newline() => RelativeRedirect.IsSameSiteRelative("/\n/evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_stripped_carriage_return() => RelativeRedirect.IsSameSiteRelative("/\r/evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_header_injection_payload() => RelativeRedirect.IsSameSiteRelative("/a\r\nSet-Cookie: x=y").ShouldBeFalse();
    [Fact] void should_reject_a_null_byte() => RelativeRedirect.IsSameSiteRelative("/dashboard\0").ShouldBeFalse();
    [Fact] void should_reject_a_space() => RelativeRedirect.IsSameSiteRelative("/ /evil.test").ShouldBeFalse();
    [Fact] void should_reject_a_delete_character() => RelativeRedirect.IsSameSiteRelative("/dashboard").ShouldBeFalse();

    [Fact] void should_reject_an_absolute_https_target() => RelativeRedirect.IsSameSiteRelative("https://evil.test").ShouldBeFalse();
    [Fact] void should_reject_an_absolute_http_target() => RelativeRedirect.IsSameSiteRelative("http://evil.test/phish").ShouldBeFalse();
    [Fact] void should_reject_a_javascript_target() => RelativeRedirect.IsSameSiteRelative("javascript:alert(1)").ShouldBeFalse();
    [Fact] void should_reject_a_data_target() => RelativeRedirect.IsSameSiteRelative("data:text/html,<script>alert(1)</script>").ShouldBeFalse();

    [Fact] void should_accept_the_application_root() => RelativeRedirect.IsSameSiteRelative("/").ShouldBeTrue();
    [Fact] void should_accept_a_simple_path() => RelativeRedirect.IsSameSiteRelative("/dashboard").ShouldBeTrue();
    [Fact] void should_accept_a_nested_path() => RelativeRedirect.IsSameSiteRelative("/dashboard/reports/2026").ShouldBeTrue();
    [Fact] void should_accept_a_path_with_a_query() => RelativeRedirect.IsSameSiteRelative("/dashboard?tab=overview&sort=asc").ShouldBeTrue();
    [Fact] void should_accept_a_path_with_a_fragment() => RelativeRedirect.IsSameSiteRelative("/dashboard#section").ShouldBeTrue();
    [Fact] void should_accept_a_path_with_percent_encoding() => RelativeRedirect.IsSameSiteRelative("/search?q=a%20b").ShouldBeTrue();
    [Fact] void should_accept_a_path_with_unreserved_punctuation() => RelativeRedirect.IsSameSiteRelative("/a-b_c~d.e").ShouldBeTrue();

    [Fact] void should_resolve_a_hostile_target_to_the_application_root() =>
        RelativeRedirect.Resolve("//evil.test").ShouldEqual(RelativeRedirect.ApplicationRoot);

    [Fact] void should_resolve_a_backslash_target_to_the_application_root() =>
        RelativeRedirect.Resolve("/\\evil.test").ShouldEqual(RelativeRedirect.ApplicationRoot);

    [Fact] void should_resolve_a_missing_target_to_the_application_root() =>
        RelativeRedirect.Resolve(null).ShouldEqual(RelativeRedirect.ApplicationRoot);

    [Fact] void should_resolve_a_same_site_target_to_itself() =>
        RelativeRedirect.Resolve("/dashboard?tab=1").ShouldEqual("/dashboard?tab=1");
}
