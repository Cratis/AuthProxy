// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

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

    /// <summary>
    /// A browser silently drops a <c>Set-Cookie</c> past 4096 bytes, and in this mode a dropped entry cookie
    /// means a caller who was admitted receives the uniform refusal for the rest of the entry's life — with
    /// nothing in any response and nothing in any log to say why, because that is the whole design.
    /// </summary>
    /// <remarks>
    /// Asserted rather than assumed because the seal is only as small as what goes into it. Every value in
    /// the transaction is authored here and fixed in size today; anything added later that a verifier or a
    /// deployment can influence would cross this bound long before anybody noticed.
    /// </remarks>
    [Fact]
    void should_issue_a_cookie_the_browser_will_keep() =>
        Encoding.UTF8.GetByteCount(IssuedCookieHeader()).ShouldBeLessThan(4096);
}
