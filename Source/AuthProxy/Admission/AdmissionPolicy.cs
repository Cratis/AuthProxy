// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Decides whether a request is answered at all, from what the browser presents and nothing else.
/// </summary>
/// <param name="protector">The protector recovering the entry transaction.</param>
/// <param name="timeProvider">The source of the current time.</param>
/// <remarks>
/// Every question this answers is closed by default. An entry transaction that is absent, unreadable,
/// altered, truncated, issued under another key ring, missing its own values or expired all resolve to the
/// same answer, and so does a provider callback arriving without an in-flight handshake cookie.
/// <para>
/// The mode is read the same way: only <see cref="C.AdmissionMode.Public"/> opens the contract, so a value
/// the proxy cannot recognize closes it rather than opening it.
/// </para>
/// </remarks>
public class AdmissionPolicy(IEntryTransactionProtector protector, TimeProvider timeProvider) : IAdmissionPolicy
{
    /// <inheritdoc/>
    public bool IsConfigured(C.AuthProxy config) => config.Admission.Mode != C.AdmissionMode.Public;

    /// <inheritdoc/>
    public bool IsPresentation(HttpContext context, C.AuthProxy config) =>
        config.Admission.Capability is { } capability
        && !string.IsNullOrWhiteSpace(capability.Path)
        && capability.Path.StartsWith('/')
        && context.Request.Path.Equals(new PathString(capability.Path), StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc/>
    public bool IsAdmitted(HttpContext context, C.AuthProxy config)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.EntryTransaction, out var protectedTransaction)
            || string.IsNullOrWhiteSpace(protectedTransaction)
            || !protector.TryUnprotect(protectedTransaction, out var transaction)
            || transaction.ExpiresAt <= timeProvider.GetUtcNow())
        {
            return false;
        }

        return !IsProviderCallback(context) || CarriesHandshakeProof(context);
    }

    /// <inheritdoc/>
    public bool DeclaresTokenEndpoint(C.AuthProxy config) =>
        config.Admission.Mode == C.AdmissionMode.Public
        || config.Services.Values.Any(service => service.ClientCredentials is not null);

    /// <summary>
    /// Determines whether a request is a provider handing an authenticated caller back.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns><see langword="true"/> when the request is a provider callback; otherwise <see langword="false"/>.</returns>
    static bool IsProviderCallback(HttpContext context) =>
        context.Request.Path.Value?.StartsWith(WellKnownPaths.SignInPrefix, StringComparison.OrdinalIgnoreCase) ?? false;

    /// <summary>
    /// Determines whether a callback carries a cookie shaped like the per-attempt state the OAuth and
    /// OpenID Connect middleware write while a handshake is in flight.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns><see langword="true"/> when such a cookie is present; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// It is a shape check and not a proof, and the difference matters: a caller writes their own cookie
    /// names, so anything named <c>.AspNetCore.Correlation.</c>-something satisfies this. What it buys is
    /// that an entry transaction alone does not carry a callback — a caller replaying a provider callback
    /// path has to have been through a handshake this proxy started, or invent a cookie that says they
    /// were. The value of that cookie is never read here.
    /// <para>
    /// The authoritative check is downstream and unchanged: the authentication handler unprotects its own
    /// correlation cookie and refuses a callback whose state does not match, and that is what actually
    /// rejects a forged one. This is a cheap narrowing in front of it, not a second gate.
    /// </para>
    /// </remarks>
    static bool CarriesHandshakeProof(HttpContext context) =>
        context.Request.Cookies.Keys.Any(name =>
            name.StartsWith(Cookies.CorrelationPrefix, StringComparison.Ordinal)
            || name.StartsWith(Cookies.NoncePrefix, StringComparison.Ordinal));
}
