// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for the session-preserving credential-linking flow.
/// </summary>
/// <remarks>
/// The link flow lets an already signed-in user prove control of an additional identity-provider login
/// and associate it with their existing account, without ever replacing their primary session. AuthProxy
/// runs a second OAuth challenge for the requested provider and, on the callback, posts the freshly
/// authenticated subject to the configured <see cref="ExchangeUrl"/> instead of signing the new identity
/// in. This mirrors the invite-exchange callback (<see cref="Invite.ExchangeUrl"/>).
/// </remarks>
public class Link
{
    /// <summary>
    /// Gets or sets the absolute URL of the application endpoint that records the freshly authenticated
    /// subject for a link, e.g. <c>https://studio.example.com/api/internal/identity-providers/link</c>.
    /// AuthProxy posts <c>{ subject, identityProvider }</c> to it with the one-time link token supplied by
    /// the application as the bearer token, exactly as the invite exchange does.
    /// Leave empty to disable the link callback.
    /// </summary>
    public string ExchangeUrl { get; set; } = string.Empty;
}
