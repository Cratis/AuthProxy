// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for a single service that the auth proxy can route to.
/// </summary>
public class Service
{
    /// <summary>
    /// The time AuthProxy waits for the identity endpoint of a service that states no timeout of its own and
    /// treats its answer as an authorization decision.
    /// </summary>
    /// <remarks>
    /// Matched to the back-channel client-credentials verifier, which is the same shape of call — a
    /// synchronous request to a backing service standing between a caller and a decision.
    /// </remarks>
    public static readonly TimeSpan DefaultIdentityVerificationTimeout = TimeSpan.FromSeconds(10);

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
    /// Gets or sets the authorization requirements that apply to requests routed to this service.
    /// </summary>
    /// <remarks>
    /// These are applied <em>in addition to</em> any declared at the root — a service can narrow who gets
    /// in, never widen it. Leave unset to require only what the root requires.
    /// <para>
    /// The service a request targets is resolved the way the route table resolves it: the single
    /// configured service when there is only one, otherwise the <c>Service-ID</c> header or the
    /// <c>service</c> query parameter. A request in a multi-service deployment that names no service
    /// matches no service route either, so only the root requirements apply to it.
    /// </para>
    /// </remarks>
    public Authorization? Authorization { get; set; }

    /// <summary>
    /// Gets or sets whether to call the <c>/.cratis/me</c> identity endpoint on this service
    /// to enrich the identity details cookie. Defaults to <see langword="true"/> when a Backend is configured.
    /// </summary>
    public bool? ResolveIdentityDetails { get; set; }

    /// <summary>
    /// Gets or sets what this service's <c>/.cratis/me</c> answer means. Defaults to
    /// <see cref="IdentityVerificationMode.BestEffort"/>, the released behavior.
    /// </summary>
    /// <remarks>
    /// <see cref="ResolveIdentityDetails"/> decides whether the endpoint is called; this decides what the
    /// answer is worth. They are deliberately separate settings because they are separate questions — a
    /// service can be asked for details it is allowed to fail to supply, or asked for a decision it is not.
    /// <para>
    /// Set this to <see cref="IdentityVerificationMode.Required"/> only for a service that genuinely answers
    /// <c>/.cratis/me</c> with an authorization verdict. Every failure to obtain that verdict then denies
    /// the request, which is the point — but it also means an outage of that one service takes the whole
    /// proxied surface down with it, deliberately, rather than serving callers whose access nobody could
    /// confirm.
    /// </para>
    /// <para>
    /// When several services take part, every one of them declaring
    /// <see cref="IdentityVerificationMode.Required"/> has to answer with an explicit positive. Requirements
    /// are added together and never widened, the same way service authorization requirements compose.
    /// </para>
    /// </remarks>
    public IdentityVerificationMode IdentityVerification { get; set; } = IdentityVerificationMode.BestEffort;

    /// <summary>
    /// Gets or sets how long AuthProxy waits for this service's <c>/.cratis/me</c> answer before treating
    /// the call as failed. Leave unset to let the mode decide — see
    /// <see cref="EffectiveIdentityVerificationTimeout"/>. Set to zero or a negative value to leave the wait
    /// unbounded.
    /// </summary>
    /// <remarks>
    /// A stated value is honored in both modes. It is deliberately nullable rather than defaulted, because
    /// "the deployment asked for ten seconds" and "the deployment said nothing" are different facts and only
    /// the second one may be answered differently per mode.
    /// </remarks>
    public TimeSpan? IdentityVerificationTimeout { get; set; }

    /// <summary>
    /// Gets how long AuthProxy actually waits for this service's <c>/.cratis/me</c> answer.
    /// </summary>
    /// <remarks>
    /// A bound on the wait is a property of fail-closed verification, not of enrichment, so an unstated
    /// timeout resolves per mode.
    /// <para>
    /// Under <see cref="IdentityVerificationMode.Required"/> the call stands between a caller and a
    /// decision. Without a bound it inherits the ambient 100-second client default, so a service that
    /// accepts connections and then stops answering holds every authenticated request open for a minute and
    /// a half each — a denial-of-service surface on its own, and the difference between a bounded refusal
    /// and an unbounded hang. <see cref="DefaultIdentityVerificationTimeout"/> applies.
    /// </para>
    /// <para>
    /// Under <see cref="IdentityVerificationMode.BestEffort"/> the call only enriches, and the released
    /// proxy waited on the ambient client default. Imposing a shorter bound nobody asked for would not
    /// refuse anything — it would admit the caller with that service's details silently missing, which is a
    /// worse failure than the slow answer it replaces because nothing downstream can tell the difference.
    /// The released wait is kept until a deployment states otherwise.
    /// </para>
    /// <para>
    /// The wait is bound to the caller's own request lifetime in both modes, so a client that goes away
    /// stops occupying the proxy whatever this resolves to.
    /// </para>
    /// </remarks>
    public TimeSpan EffectiveIdentityVerificationTimeout =>
        IdentityVerificationTimeout
        ?? (IdentityVerification == IdentityVerificationMode.Required ? DefaultIdentityVerificationTimeout : TimeSpan.Zero);

    /// <summary>
    /// Gets a value indicating whether this service's identity endpoint is called at all.
    /// </summary>
    /// <remarks>
    /// The rule is the one the resolver has always applied — a service takes part when it declares a backend
    /// and has not opted out — and it is stated here because two places now depend on the same answer: the
    /// resolver, deciding whom to ask, and the authorization cache, deciding whether a positive may be
    /// sealed into a cookie at all. They must never disagree about it.
    /// </remarks>
    public bool ParticipatesInIdentityResolution => Backend is not null && (ResolveIdentityDetails ?? true);

    /// <summary>
    /// Gets or sets the back-channel client-credentials configuration for this service.
    /// When configured, AuthProxy can verify client credentials against the service and mint scoped bearer tokens.
    /// </summary>
    public ServiceClientCredentials? ClientCredentials { get; set; }
}
