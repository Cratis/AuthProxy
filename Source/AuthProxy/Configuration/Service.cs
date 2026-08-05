// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for a single service that the auth proxy can route to.
/// </summary>
public class Service
{
    /// <summary>
    /// Gets or sets the backend (API) endpoint for this service.
    /// </summary>
    public ServiceEndpoint? Backend { get; set; }

    /// <summary>
    /// Gets or sets the frontend (SPA / static assets) endpoint for this service.
    /// </summary>
    public ServiceEndpoint? Frontend { get; set; }

    /// <summary>
    /// Gets or sets the registration endpoint for this service.
    /// This is currently used by the lobby configuration to identify where new users should be sent
    /// after the AuthProxy registration flow completes.
    /// </summary>
    public ServiceEndpoint? Registration { get; set; }

    /// <summary>
    /// Gets or sets the request paths on this service that are served to unauthenticated callers.
    /// </summary>
    /// <remarks>
    /// Without this, every path behind the proxy requires a session: an unauthenticated request is
    /// answered by <c>SelectProviderMiddleware</c> with the provider-selection page — at <c>HTTP 200</c>,
    /// so a non-browser caller records success and never retries — and any request that does reach the
    /// reverse proxy is refused by the default authorization policy. An application that legitimately
    /// serves some paths anonymously (a magic-link landing page, a signed-token report, a public webhook
    /// receiver) has no way to express that. Listing those paths here does.
    /// <para>
    /// Each entry is a path prefix, matched case-insensitively on segment boundaries exactly like the
    /// built-in invite / registration / authentication-UI paths: <c>/portal</c> matches <c>/portal</c> and
    /// <c>/portal/anything</c>, but not <c>/portalx</c>. Because it is a prefix, an entry covers
    /// everything below it, so name the specific leaf path whenever a sibling under the same parent is not
    /// public. An entry that is not a plain rooted path of literal segments — blank, unrooted, the bare
    /// <c>/</c>, or carrying a route-template character — is discarded, leaving that path authenticated.
    /// See <see cref="AnonymousPaths.TryNormalize"/> for the exact rule.
    /// </para>
    /// <para>
    /// This does not weaken the identity boundary. Requests still flow through AuthProxy, so
    /// <c>TenancyMiddleware</c> strips inbound <c>x-ms-client-principal*</c> and <c>Tenant-ID</c> headers
    /// as it does for every request, and no principal headers are injected for a caller with no session.
    /// The application stays responsible for authorizing these paths — this only stops the proxy from
    /// demanding a login before the application is ever reached.
    /// </para>
    /// </remarks>
    public IList<string> AnonymousPaths { get; set; } = [];

    /// <summary>
    /// Gets or sets whether to call the <c>/.cratis/me</c> identity endpoint on this service
    /// to enrich the identity details cookie. Defaults to <see langword="true"/> when a Backend is configured.
    /// </summary>
    public bool? ResolveIdentityDetails { get; set; }

    /// <summary>
    /// Gets or sets the back-channel client-credentials configuration for this service.
    /// When configured, AuthProxy can verify client credentials against the service and mint scoped bearer tokens.
    /// </summary>
    public ServiceClientCredentials? ClientCredentials { get; set; }
}
