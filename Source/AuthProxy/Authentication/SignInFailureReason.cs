// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The well-known values AuthProxy uses to tell the provider-selection page why a caller landed on it,
/// carried in the <see cref="QueryKey"/> query-string parameter.
/// </summary>
/// <remarks>
/// A failed sign-in must never surface as a bare error page — the browser is redirected back to provider
/// selection with one of these reasons so the page can show the person what happened and offer the way
/// forward: trying again. The values are part of the page contract, so a custom
/// <c>select-provider.html</c> can rely on them.
/// </remarks>
public static class SignInFailureReason
{
    /// <summary>
    /// The query-string key the reason is carried in.
    /// </summary>
    public const string QueryKey = "reason";

    /// <summary>
    /// The identity-provider round-trip did not complete — the provider callback could not be validated
    /// (a stale or missing correlation cookie, an invalid state, a replayed callback URL).
    /// </summary>
    public const string RemoteFailure = "remote-failure";

    /// <summary>
    /// The identity provider reported that access was denied — typically the person cancelled the sign-in
    /// or declined the consent prompt.
    /// </summary>
    public const string AccessDenied = "access-denied";

    /// <summary>
    /// The session existed but could no longer be turned into a forwardable identity, so it was terminated
    /// and a fresh sign-in is required.
    /// </summary>
    public const string InvalidSession = "invalid-session";
}
