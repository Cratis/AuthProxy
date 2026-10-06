// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Claims;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Display-only email evidence captured by a validated, correlated invitation exchange.
/// It lives only on that request and never participates in recipient authorization.
/// </summary>
/// <param name="InvitedEmail">The invitation's captured recipient address.</param>
/// <param name="AssertedEmail">The single usable address supplied by the provider, or empty.</param>
sealed record InvitationPageEmails(string InvitedEmail, string AssertedEmail)
{
    static readonly object _itemKey = new();

    /// <summary>
    /// Clears display evidence before evaluating another invitation on the request.
    /// </summary>
    /// <param name="context">The request.</param>
    internal static void Clear(HttpContext context) => context.Items.Remove(_itemKey);

    /// <summary>
    /// Captures display evidence after the invitation and authentication binding have been checked.
    /// </summary>
    /// <param name="context">The correlated request.</param>
    /// <param name="emails">The captured email evidence.</param>
    internal static void Remember(HttpContext context, InvitationPageEmails emails) => context.Items[_itemKey] = emails;

    /// <summary>
    /// Gets encoded substitutions for an invitation's email-binding failure page.
    /// </summary>
    /// <param name="context">The correlated request.</param>
    /// <param name="includeAssertedEmail">Whether the mismatch page may show the asserted address.</param>
    /// <returns>The substitutions, or null when no validated evidence was captured.</returns>
    internal static IReadOnlyDictionary<string, string>? ForRequest(HttpContext context, bool includeAssertedEmail) =>
        context.Items.TryGetValue(_itemKey, out var value) && value is InvitationPageEmails emails
            ? emails.Substitutions(includeAssertedEmail)
            : null;

    /// <summary>
    /// Gets the encoded recipient for a validated invitation's provider-selection page.
    /// </summary>
    /// <param name="validator">The invitation claim reader.</param>
    /// <param name="token">The already validated invitation capability.</param>
    /// <param name="emailClaim">The configured recipient claim.</param>
    /// <returns>The display substitutions; the asserted address is always empty.</returns>
    internal static IReadOnlyDictionary<string, string> ForSelection(IInviteTokenValidator validator, string token, string? emailClaim) =>
        new InvitationPageEmails(!string.IsNullOrWhiteSpace(emailClaim) && validator.TryGetClaim(token, emailClaim, out var email) ? email : string.Empty, string.Empty).Substitutions(includeAssertedEmail: false);

    /// <summary>
    /// Captures a single explicit email claim without inferring an address from a username.
    /// </summary>
    /// <param name="principal">The authenticated provider principal.</param>
    /// <returns>The usable address, or empty when absent or ambiguous.</returns>
    internal static string AssertedAddress(ClaimsPrincipal principal)
    {
        var claims = principal.Claims.Where(claim => claim.Type == "email" || claim.Type == ClaimTypes.Email).ToArray();
        return claims.Length == 1 && IsUsableAddress(claims[0].Value) ? claims[0].Value : string.Empty;
    }

    static bool IsUsableAddress(string email) =>
        email.Length <= 2048 && string.Equals(email, email.Trim(), StringComparison.Ordinal) && InviteMiddleware.IsAnEmailAddress(email);

    /// <summary>
    /// Encodes display text and braces so an address cannot introduce another replacement token.
    /// </summary>
    /// <param name="email">The captured address.</param>
    /// <returns>HTML-encoded text, or empty for an unusable address.</returns>
    static string Encode(string email) =>
        WebUtility.HtmlEncode(IsUsableAddress(email) ? email : string.Empty).Replace("{", "&#123;", StringComparison.Ordinal).Replace("}", "&#125;", StringComparison.Ordinal);

    Dictionary<string, string> Substitutions(bool includeAssertedEmail) => new()
    {
        ["{{invitedEmail}}"] = Encode(InvitedEmail),
        ["{{assertedEmail}}"] = includeAssertedEmail ? Encode(AssertedEmail) : string.Empty,
    };
}
