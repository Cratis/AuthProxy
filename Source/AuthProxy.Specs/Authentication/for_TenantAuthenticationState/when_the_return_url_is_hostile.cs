// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_TenantAuthenticationState;

/// <summary>
/// The <c>returnUrl</c> the login endpoint accepts must never survive as an off-site redirect.
/// <para>
/// This is the most exposed redirect sink in AuthProxy and the most valuable one to an attacker. The
/// endpoint that feeds it — <c>/.cratis/login/{scheme}</c> — is <c>AllowAnonymous</c>, so the value is
/// attacker-supplied by default. What it becomes is the challenge's <c>RedirectUri</c>,
/// which ASP.NET's remote authentication handler hands straight to <c>Response.Redirect</c> once the
/// identity provider returns, without validating it. The victim therefore sees a link on the real domain,
/// completes a genuine sign-in at the genuine provider, and only then lands wherever the link said —
/// every signal a careful person is taught to check having already passed.
/// </para>
/// <para>
/// The check that used to guard it was <c>returnUrl.StartsWith('/')</c>, which <c>//evil.test</c> and
/// <c>/\evil.test</c> both satisfy while navigating off-site. An absolute URL is reduced to its path and
/// query rather than refused, so a caller that sends its own origin keeps working — the host is dropped,
/// never honored.
/// </para>
/// </summary>
public class when_the_return_url_is_hostile : Specification
{
    ITenantResolver _tenantResolver;
    DefaultHttpContext _context;

    void Establish()
    {
        _tenantResolver = Substitute.For<ITenantResolver>();
        _tenantResolver
            .TryResolve(Arg.Any<HttpContext>(), out Arg.Any<TenantResolutionResult>())
            .Returns(false);

        _context = new DefaultHttpContext();
    }

    string RedirectFor(string? returnUrl) =>
        TenantAuthenticationState.CreateChallengeProperties(_context, _tenantResolver, returnUrl!).RedirectUri!;

    [Fact] void should_refuse_a_protocol_relative_target() => RedirectFor("//evil.test").ShouldEqual("/");
    [Fact] void should_refuse_a_protocol_relative_target_with_a_path() => RedirectFor("//evil.test/phish").ShouldEqual("/");
    [Fact] void should_refuse_three_leading_slashes() => RedirectFor("///evil.test").ShouldEqual("/");
    [Fact] void should_refuse_a_backslash_authority() => RedirectFor("/\\evil.test").ShouldEqual("/");
    [Fact] void should_refuse_a_mixed_slash_authority() => RedirectFor("/\\/evil.test").ShouldEqual("/");
    [Fact] void should_refuse_a_stripped_tab() => RedirectFor("/\t/evil.test").ShouldEqual("/");
    [Fact] void should_refuse_a_header_injection_payload() => RedirectFor("/a\r\nSet-Cookie: x=y").ShouldEqual("/");
    [Fact] void should_refuse_a_javascript_target() => RedirectFor("javascript:alert(1)").ShouldEqual("/");
    [Fact] void should_refuse_an_empty_target() => RedirectFor(string.Empty).ShouldEqual("/");

    [Fact] void should_reduce_an_absolute_foreign_url_to_its_path() => RedirectFor("https://evil.test/phish").ShouldEqual("/phish");
    [Fact] void should_reduce_an_absolute_foreign_url_keeping_its_query() => RedirectFor("https://evil.test/phish?a=b").ShouldEqual("/phish?a=b");
    [Fact] void should_root_a_bare_relative_target() => RedirectFor("dashboard").ShouldEqual("/dashboard");

    [Fact] void should_keep_a_same_site_target() => RedirectFor("/dashboard").ShouldEqual("/dashboard");
    [Fact] void should_keep_a_same_site_target_with_a_query() => RedirectFor("/dashboard?tab=overview").ShouldEqual("/dashboard?tab=overview");
    [Fact] void should_keep_a_nested_same_site_target() => RedirectFor("/a/b/c").ShouldEqual("/a/b/c");
}
