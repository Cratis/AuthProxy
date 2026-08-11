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
/// altered, truncated, issued under another key ring or expired all resolve to the same answer, and so does
/// a provider callback arriving without the framework's own handshake proof.
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
    /// Determines whether a callback carries the framework's own proof that it belongs to a handshake this
    /// browser started.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns><see langword="true"/> when the handshake proof is present; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// The entry transaction says the browser was admitted; it says nothing about a handshake being in
    /// flight. The correlation and nonce cookies the OAuth and OpenID Connect middleware write per attempt
    /// say the opposite — they prove a handshake without saying anything about admission. A callback needs
    /// both, so neither one alone is a way in.
    /// </remarks>
    static bool CarriesHandshakeProof(HttpContext context) =>
        context.Request.Cookies.Keys.Any(name =>
            name.StartsWith(Cookies.CorrelationPrefix, StringComparison.Ordinal)
            || name.StartsWith(Cookies.NoncePrefix, StringComparison.Ordinal));
}
