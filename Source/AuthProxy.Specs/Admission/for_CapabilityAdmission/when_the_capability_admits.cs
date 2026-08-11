// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityAdmission;

/// <summary>
/// An admitted presentation leaves exactly one thing behind: the sealed record that a verifier said yes.
/// <para>
/// The seal has to contain nothing of the capability, and that is asserted against the raw bytes of the
/// cookie rather than against the record that went into it — the record is what the code intended to
/// store, the cookie is what the browser and every proxy between here and it actually gets.
/// </para>
/// </summary>
public class when_the_capability_admits : given.a_capability_admission
{
    void Establish()
    {
        Presenting(Capability);
        VerifierAdmitting();
    }

    async Task Because() => _admitted = await _admission.TryAdmit(_context, _config);

    [Fact] void should_admit_the_caller() => _admitted.ShouldBeTrue();
    [Fact] void should_answer_with_no_content() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status204NoContent);
    [Fact] void should_issue_exactly_one_cookie() => _context.Response.Headers.SetCookie.Count.ShouldEqual(1);
    [Fact] void should_issue_the_entry_transaction() => IssuedCookieHeader().StartsWith($"{Cookies.EntryTransaction}=", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_keep_the_cookie_away_from_script() => IssuedCookieHeader().Contains("httponly", StringComparison.OrdinalIgnoreCase).ShouldBeTrue();
    [Fact] void should_keep_the_cookie_on_same_site_navigation() => IssuedCookieHeader().Contains("samesite=lax", StringComparison.OrdinalIgnoreCase).ShouldBeTrue();
    [Fact] void should_scope_the_cookie_to_the_whole_host() => IssuedCookieHeader().Contains("path=/", StringComparison.OrdinalIgnoreCase).ShouldBeTrue();
    [Fact] void should_bound_the_cookie_by_the_entry_lifetime() => IssuedCookieHeader().Contains("max-age=600", StringComparison.OrdinalIgnoreCase).ShouldBeTrue();
    [Fact] void should_not_mark_a_plain_http_cookie_secure() => IssuedCookieHeader().Contains("secure", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();

    [Fact]
    void should_put_no_part_of_the_capability_in_the_cookie()
    {
        var raw = IssuedCookieValue();
        for (var start = 0; start + 6 <= Capability.Length; start++)
        {
            raw.Contains(Capability.Substring(start, 6), StringComparison.Ordinal).ShouldBeFalse();
        }
    }

    [Fact]
    void should_seal_a_transaction_that_expires_with_the_entry_lifetime()
    {
        _protector.TryUnprotect(IssuedCookieValue(), out var transaction).ShouldBeTrue();
        transaction.ExpiresAt.ShouldEqual(_time.GetUtcNow().AddMinutes(10));
    }

    [Fact]
    void should_carry_the_context_the_verifier_asked_for()
    {
        _protector.TryUnprotect(IssuedCookieValue(), out var transaction).ShouldBeTrue();
        transaction.Context["scope"].ShouldEqual("opaque");
    }
}
