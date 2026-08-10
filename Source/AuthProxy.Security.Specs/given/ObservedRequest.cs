// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Represents the state a request was normalized to by the time the proxy was done with it.
/// </summary>
/// <param name="RemoteIpAddress">The address every later decision treats as the client's.</param>
/// <param name="Scheme">The scheme every later decision treats as the browser's — which is what settles cookie <c>Secure</c> and the proxy's own public origin.</param>
/// <param name="Host">The host the request is treated as having arrived at.</param>
/// <param name="PathBase">The path prefix the request is treated as being mounted under.</param>
/// <param name="RemainingForwardedFor">What was left of <c>X-Forwarded-For</c> after the middleware consumed from it.</param>
/// <remarks>
/// These four values are the whole of what forwarded headers can change, and every downstream consequence in
/// the proxy — the address recorded against a sign-in, the <c>Secure</c> flag on eleven cookies, the OIDC
/// <c>post_logout_redirect_uri</c>, the post-logout origin allow-list — is derived from them. Asserting on
/// them directly is what makes a spec about the boundary rather than about one of its symptoms.
/// </remarks>
public sealed record ObservedRequest(
    string RemoteIpAddress,
    string Scheme,
    string Host,
    string PathBase,
    string RemainingForwardedFor);
