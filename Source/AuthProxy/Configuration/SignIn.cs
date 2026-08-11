// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for sign-in notifications.
/// </summary>
/// <remarks>
/// When a user who was signed out completes an interactive identity-provider login and a fresh session is
/// established, AuthProxy posts a small notification to the configured <see cref="NotifyUrl"/> so the
/// application can record the sign-in (for example to alert the user of a new sign-in). It is a
/// service-to-service back-channel, mirroring the invite exchange (<see cref="Invite.ExchangeUrl"/>) and the
/// credential link callback (<see cref="Link.ExchangeUrl"/>). The notification fires only on a genuine
/// logged-out to signed-in transition — never on an already-authenticated proxied request or a session that
/// is merely being reused.
/// </remarks>
public class SignIn
{
    /// <summary>
    /// Gets or sets the absolute URL of the application endpoint that records a completed sign-in,
    /// e.g. <c>https://studio.example.com/api/internal/sign-ins</c>.
    /// AuthProxy posts <c>{ subject, identityProvider, ipAddress, location, browser, operatingSystem, userAgent }</c>
    /// to it. Leave empty to disable sign-in notifications.
    /// </summary>
    /// <remarks>
    /// With <see cref="Attestation"/> configured this URL must carry no query. The signed route binding is the
    /// RFC 9449 <c>htu</c>, which covers the path only, so a query would travel unsigned — a captured
    /// notification could then be replayed against a different query and still verify.
    /// </remarks>
    public string NotifyUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signed-envelope configuration for sign-in notifications.
    /// Set this section to have AuthProxy authenticate every notification with a short-lived RS256 JWS bound
    /// to the exact request it accompanies.
    /// Leave it unset — the default — and notifications are posted unsigned, exactly as they always have been.
    /// </summary>
    public SignInAttestation? Attestation { get; set; }
}
