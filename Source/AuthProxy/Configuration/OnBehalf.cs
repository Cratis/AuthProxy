// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for on-behalf sessions: a support person, or an agent working for support,
/// signed in with their own identity, acting on behalf of a specific user in a specific tenant for one issue.
/// </summary>
/// <remarks>
/// Leave the section out — the default — and the feature does not exist: the AuthProxy endpoints answer
/// <c language="text">404</c>, no grant is ever checked and nothing is forwarded differently. With it, AuthProxy only issues
/// an on-behalf session after the application named by <see cref="Service"/> confirms a live grant, re-checks that
/// grant while the session lasts, and tells the application when the session starts and ends.
/// </remarks>
public class OnBehalf
{
    /// <summary>
    /// The default for <see cref="RecheckInterval"/>.
    /// </summary>
    public static readonly TimeSpan DefaultRecheckInterval = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The default for <see cref="MaximumLifetime"/>.
    /// </summary>
    public static readonly TimeSpan DefaultMaximumLifetime = TimeSpan.FromHours(1);

    /// <summary>
    /// The default for <see cref="Timeout"/>.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets or sets the name of the configured service whose backend answers the grant check and receives the
    /// session notifications. It must name an entry in <see cref="AuthProxy.Services"/> that declares a backend.
    /// </summary>
    public string Service { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the claims the actor — the support person or agent — must carry to start an on-behalf session.
    /// At least one requirement is mandatory, so a deployment has to say who support is.
    /// </summary>
    /// <remarks>
    /// These are evaluated against the actor's own principal, in addition to the deployment's root and service
    /// requirements every request already has to pass. The application's grant check is still asked; this only
    /// keeps everybody else from asking it.
    /// </remarks>
    public Authorization ActorAuthorization { get; set; } = new();

    /// <summary>
    /// Gets or sets how long a confirmed grant is trusted before it is asked about again. Defaults to
    /// <see cref="DefaultRecheckInterval"/>; must be between one second and five minutes.
    /// </summary>
    /// <remarks>
    /// This is the longest a revoked grant can go on being honored. A grant is never trusted past the
    /// <c language="text">validUntil</c> the application stated for it, whatever this says.
    /// </remarks>
    public TimeSpan RecheckInterval { get; set; } = DefaultRecheckInterval;

    /// <summary>
    /// Gets or sets the longest an on-behalf session may last, however long the grant is valid. Defaults to
    /// <see cref="DefaultMaximumLifetime"/>; must be between one minute and twenty-four hours.
    /// </summary>
    public TimeSpan MaximumLifetime { get; set; } = DefaultMaximumLifetime;

    /// <summary>
    /// Gets or sets how long AuthProxy waits for the grant check and the session notifications. Defaults to
    /// <see cref="DefaultTimeout"/>; must be between one and sixty seconds.
    /// </summary>
    public TimeSpan Timeout { get; set; } = DefaultTimeout;

    /// <summary>
    /// Gets or sets the signing configuration for the grant check, the session notifications and the assertion
    /// forwarded with every on-behalf request. Required: an on-behalf identity is never forwarded unsigned.
    /// </summary>
    public OnBehalfAttestation? Attestation { get; set; }
}
