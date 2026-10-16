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
    /// e.g. <c language="text">https://studio.example.com/api/internal/sign-ins</c>.
    /// AuthProxy posts <c language="text">{ subject, identityProvider, ipAddress, location, browser, operatingSystem, userAgent }</c>
    /// to it. Leave empty to disable sign-in notifications.
    /// </summary>
    /// <remarks>
    /// With <see cref="Attestation"/> configured this URL must carry no query. The signed route binding is the
    /// RFC 9449 <c language="text">htu</c>, which covers the path only, so a query would travel unsigned — a captured
    /// notification could then be replayed against a different query and still verify.
    /// </remarks>
    public string NotifyUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the one host the identity-provider handshake runs on, as <c language="text">host</c> or <c language="text">host:port</c>,
    /// for example <c language="text">auth.cratis.io</c>. Leave empty — the default — and every host completes its own handshake.
    /// </summary>
    /// <remarks>
    /// With a callback host, a sign-in that starts on another host is sent to this one, runs the whole OAuth or OIDC
    /// handshake there and returns to the original host afterwards, so the provider needs a single registered callback
    /// and a single post-logout address however many hosts one proxy serves. It requires
    /// <see cref="Session.CookieDomain"/>, because the session has to be valid on the host the person returns to, and
    /// the host has to lie inside that domain.
    /// <para>
    /// Setting it also lets a sign-in or sign-out return to an absolute address, but only to a host a service declares
    /// in <see cref="Service.Hosts"/> or to an origin in <see cref="Logout.AllowedRedirectOrigins"/>, and only inside the
    /// cookie domain. Invitations, credential links and registration keep running on the host they start on.
    /// </para>
    /// </remarks>
    public string CallbackHost { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signed-envelope configuration for sign-in notifications.
    /// Set this section to have AuthProxy authenticate every notification with a short-lived RS256 JWS bound
    /// to the exact request it accompanies.
    /// Leave it unset — the default — and notifications are posted unsigned, exactly as they always have been.
    /// </summary>
    public SignInAttestation? Attestation { get; set; }
}
