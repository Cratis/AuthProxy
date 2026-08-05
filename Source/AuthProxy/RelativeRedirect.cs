// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Decides whether a caller-supplied redirect target is a same-site relative URL, and is the single place
/// that decision is made.
/// </summary>
/// <remarks>
/// AuthProxy hands the browser a redirect target the caller supplied in four places — the login endpoint's
/// <c>returnUrl</c>, the link flow's <c>returnUrl</c>, tenant selection's <c>returnUrl</c>, and logout's
/// <c>redirect</c>. Each had grown its own version of "is this relative", and they disagreed: one accepted
/// <c>//evil.test</c> outright, and the two that rejected it still accepted <c>/\evil.test</c>. An open
/// redirect on the authentication proxy is the strongest phishing primitive a system can offer — the
/// victim sees the real domain, completes a real login at the real identity provider, and only then lands
/// on the attacker's page — so the check lives here once rather than being re-derived per call site.
/// <para>
/// A single leading <c>/</c> is not enough to be same-site, because the browser decides what a
/// <c>Location</c> means, not the string's first character:
/// </para>
/// <list type="bullet">
///   <item><c>//evil.test</c> is protocol-relative and navigates off-site.</item>
///   <item><c>/\evil.test</c> is the same thing to every major browser, which normalize <c>\</c> to
///     <c>/</c> in the authority position.</item>
///   <item><c>/</c> followed by a tab, carriage return or newline is <em>also</em> the same thing:
///     browsers strip those characters from a URL before parsing it, so <c>/\tevil.test</c> is fetched as
///     <c>//evil.test</c>. Control characters are what make a header-injection payload too, so they are
///     refused rather than stripped.</item>
/// </list>
/// </remarks>
public static class RelativeRedirect
{
    /// <summary>
    /// The application root, used as the safe destination when a requested target is not allowed.
    /// </summary>
    public const string ApplicationRoot = "/";

    /// <summary>
    /// Determines whether a target is a relative URL that can only navigate within this site.
    /// </summary>
    /// <param name="url">The caller-supplied target.</param>
    /// <returns><see langword="true"/> when the target is same-site relative; otherwise <see langword="false"/>.</returns>
    public static bool IsSameSiteRelative(string? url)
    {
        if (string.IsNullOrEmpty(url) || url[0] != '/')
        {
            return false;
        }

        // The second character is what turns a path into an authority. Both spellings are refused, so
        // neither '//evil.test' nor '/\evil.test' can be handed to a browser.
        if (url.Length > 1 && (url[1] == '/' || url[1] == '\\'))
        {
            return false;
        }

        // A backslash anywhere is refused rather than reasoned about: it is a separator to some parsers
        // and a literal to others, and no legitimate return URL needs one.
        // Anything at or below space covers every control character — including the tab, carriage return
        // and newline a browser would strip, revealing a leading '//' that was not there in the string.
        foreach (var character in url)
        {
            if (character == '\\' || character <= ' ' || character == '\u007f')
            {
                return false;
            }
        }

        return Uri.TryCreate(url, UriKind.Relative, out _);
    }

    /// <summary>
    /// Resolves the effective redirect target, returning the requested value when it is same-site relative
    /// and the application root otherwise.
    /// </summary>
    /// <param name="url">The caller-supplied target.</param>
    /// <returns>The requested target when allowed; otherwise <see cref="ApplicationRoot"/>.</returns>
    public static string Resolve(string? url) => IsSameSiteRelative(url) ? url! : ApplicationRoot;
}
