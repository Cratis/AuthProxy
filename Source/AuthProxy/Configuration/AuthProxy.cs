// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the root configuration for the auth proxy.
/// </summary>
public class AuthProxy
{
    /// <summary>
    /// The configuration section key for the root auth proxy settings.
    /// </summary>
    public const string SectionKey = "Cratis:AuthProxy";

    /// <summary>
    /// The activity timeout applied to a proxied request when neither the endpoint, its service nor the
    /// root states one.
    /// </summary>
    public static readonly TimeSpan DefaultActivityTimeout = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the authentication configuration.
    /// </summary>
    public Authentication Authentication { get; set; } = new();

    /// <summary>
    /// Gets or sets the authorization configuration applied to every service — the first gate an
    /// authenticated caller has to pass before any request is forwarded.
    /// Leave it empty (the default) to authenticate without authorizing, as the proxy has always done.
    /// </summary>
    public Authorization Authorization { get; set; } = new();

    /// <summary>
    /// Gets or sets the admission configuration deciding whether AuthProxy answers anything at all to a
    /// caller who has presented nothing.
    /// Leave it at its default — <see cref="AdmissionMode.Public"/> — and the interactive contract stays
    /// exactly as public as it has always been.
    /// </summary>
    public Admission Admission { get; set; } = new();

    /// <summary>
    /// Gets or sets the browser-session hardening configuration: the bounded authentication session
    /// lifetime and the identity/tenant re-validation intervals.
    /// </summary>
    public Session Session { get; set; } = new();

    /// <summary>
    /// Gets or sets the invite system configuration.
    /// Set this section to enable invite-based onboarding.
    /// </summary>
    public Invite? Invite { get; set; }

    /// <summary>
    /// Gets or sets the credential-linking configuration.
    /// Set this section to enable the session-preserving <c language="text">/.cratis/link/{scheme}</c> flow.
    /// </summary>
    public Link? Link { get; set; }

    /// <summary>
    /// Gets or sets the sign-in notification configuration.
    /// Set this section to have AuthProxy post a notification to the application whenever a user
    /// completes an interactive sign-in.
    /// </summary>
    public SignIn? SignIn { get; set; }

    /// <summary>
    /// Gets or sets the private management listener configuration.
    /// Set this section to open a second, private listener carrying the liveness and readiness endpoints.
    /// Leave it unset — the default — and no additional socket is opened and no such endpoint exists.
    /// </summary>
    public Management? Management { get; set; }

    /// <summary>
    /// Gets or sets the logout configuration, including the post-logout redirect allow-list.
    /// </summary>
    public Logout Logout { get; set; } = new();

    /// <summary>
    /// Gets or sets the tenant verification configuration.
    /// When set, the ingress calls the configured service to confirm that a resolved
    /// tenant exists before forwarding the request.
    /// Leave unset to skip tenant verification.
    /// </summary>
    public TenantVerification? TenantVerification { get; set; }

    /// <summary>
    /// Gets or sets the absolute path to a directory containing custom error pages.
    /// Pages are looked up by their <see cref="WellKnownPageNames"/> file name inside this directory.
    /// When empty or unset the ingress uses the built-in <c language="text">Pages</c> directory.
    /// Override this by mounting a custom pages directory into the container and pointing
    /// this setting at the mount path.
    /// </summary>
    public string PagesPath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the absolute path to a directory used to persist ASP.NET Core Data Protection keys.
    /// These keys encrypt the authentication cookie and AuthProxy-issued client-credentials bearer tokens.
    /// When empty or unset, the default per-machine key ring is used, which is neither guaranteed to
    /// survive a restart nor shared across replicas. Any deployment running more than one AuthProxy
    /// instance, or that needs sessions and client-credentials tokens to survive a restart, should
    /// mount a persistent, shared volume and point this setting at it.
    /// </summary>
    public string DataProtectionKeysPath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets where the Data Protection key ring is persisted and how it is protected, for deployments
    /// that share it through Azure Blob Storage or Redis instead of a mounted volume. Leave it out to keep
    /// using <see cref="DataProtectionKeysPath"/>.
    /// </summary>
    public DataProtection DataProtection { get; set; } = new();

    /// <summary>
    /// Gets or sets the <see cref="Tenants"/>.
    /// Tenants are keyed by tenant ID string.
    /// </summary>
    public Tenants Tenants { get; set; } = new();

    /// <summary>
    /// Gets or sets the tenant resolution strategies applied in order until one resolves.
    /// </summary>
    public IList<TenantResolution> TenantResolutions { get; set; } = [];

    /// <summary>
    /// Gets or sets how long a proxied request may sit idle — with no bytes moving in either direction —
    /// before the proxy cancels it. Applies to every endpoint that states no timeout of its own and whose
    /// service states none. Leave unset for <see cref="DefaultActivityTimeout"/> (five minutes).
    /// </summary>
    /// <remarks>
    /// The clock restarts every time data is read or written, so this is an idle limit rather than a limit on
    /// the total duration. It is what ends a quiet WebSocket or Server-Sent Events stream. Must be greater
    /// than zero. See <see cref="Service.ActivityTimeout"/> and <see cref="ServiceEndpoint.ActivityTimeout"/>
    /// for the narrower settings.
    /// </remarks>
    public TimeSpan? ActivityTimeout { get; set; }

    /// <summary>
    /// Gets or sets the services configuration.
    /// Services are keyed by a friendly name (e.g. "portal", "catalog").
    /// </summary>
    public IDictionary<string, Service> Services { get; set; } = new Dictionary<string, Service>();

    /// <summary>
    /// Gets a value indicating whether any participating service treats its identity answer as an
    /// authorization decision.
    /// </summary>
    /// <remarks>
    /// One service asking to be believed is enough to change how the whole request is treated, because a
    /// remembered authorization is remembered per request rather than per service. Requirements add together
    /// and are never widened, the same way service claim requirements compose.
    /// </remarks>
    public bool RequiresIdentityVerification =>
        Services.Values.Any(service =>
            service.ParticipatesInIdentityResolution && service.IdentityVerification == IdentityVerificationMode.Required);
}
