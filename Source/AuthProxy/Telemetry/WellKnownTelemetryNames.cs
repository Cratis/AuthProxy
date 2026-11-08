// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Telemetry;

/// <summary>
/// The names of the activity source, meter, spans, metrics and attributes AuthProxy emits.
/// </summary>
/// <remarks>
/// These names are public API: dashboards and alerts depend on them, so a rename ships both names for one minor
/// release. Every attribute listed here has a small closed set of values (an enumeration written in lowercase
/// snake case); none carries a token, claim value, subject, email, cookie, secret, URL or tenant identifier.
/// </remarks>
public static class WellKnownTelemetryNames
{
    /// <summary>
    /// The instrumentation scope: the name of both the <see cref="System.Diagnostics.ActivitySource"/> and the <see cref="System.Diagnostics.Metrics.Meter"/>.
    /// </summary>
    public const string Scope = "Cratis.AuthProxy";

    /// <summary>
    /// The service name used when <c language="text">OTEL_SERVICE_NAME</c> is not set.
    /// </summary>
    public const string DefaultServiceName = "cratis-authproxy";

    /// <summary>
    /// The span covering the notification of a completed sign-in to the application.
    /// </summary>
    public const string SignInNotifySpan = "cratis.authproxy.sign_in.notify";

    /// <summary>
    /// The span covering the resolution of the identity details of a signed-in caller (<c language="text">/.cratis/me</c>).
    /// </summary>
    public const string IdentityResolveSpan = "cratis.authproxy.identity.resolve";

    /// <summary>
    /// The span covering the resolution of the tenant of a request.
    /// </summary>
    public const string TenantResolveSpan = "cratis.authproxy.tenant.resolve";

    /// <summary>
    /// The span covering the exchange of an invitation for a completed sign-in.
    /// </summary>
    public const string InviteExchangeSpan = "cratis.authproxy.invite.exchange";

    /// <summary>
    /// The span covering the validation of the access token presented on a bearer route.
    /// </summary>
    public const string BearerValidateSpan = "cratis.authproxy.bearer.validate";

    /// <summary>
    /// The counter of completed sign-ins, by outcome. Unit <c language="text">{sign_in}</c>.
    /// </summary>
    public const string SignInsMetric = "cratis.authproxy.sign_ins";

    /// <summary>
    /// The counter of identity verifications that refused the caller, by reason. Unit <c language="text">{denial}</c>.
    /// </summary>
    public const string IdentityDenialsMetric = "cratis.authproxy.identity.denials";

    /// <summary>
    /// The counter of identity result-cache lookups, by result. Unit <c language="text">{request}</c>.
    /// </summary>
    public const string IdentityCacheRequestsMetric = "cratis.authproxy.identity.cache.requests";

    /// <summary>
    /// The counter of bearer token validations, by outcome. Unit <c language="text">{validation}</c>.
    /// </summary>
    public const string BearerValidationsMetric = "cratis.authproxy.bearer.validations";

    /// <summary>
    /// The counter of invitation exchanges, by outcome. Unit <c language="text">{exchange}</c>.
    /// </summary>
    public const string InviteExchangesMetric = "cratis.authproxy.invite.exchanges";

    /// <summary>
    /// The counter of requests that could not be forwarded to a service, by error type. Unit <c language="text">{error}</c>.
    /// </summary>
    public const string UpstreamErrorsMetric = "cratis.authproxy.upstream.errors";

    /// <summary>
    /// The outcome of a sign-in notification: <c language="text">notified</c>, <c language="text">skipped</c> or <c language="text">failed</c>.
    /// </summary>
    public const string SignInOutcomeAttribute = "cratis.authproxy.sign_in.outcome";

    /// <summary>
    /// The outcome of an identity resolution: <c language="text">authorized</c> or <c language="text">denied</c>.
    /// </summary>
    public const string IdentityOutcomeAttribute = "cratis.authproxy.identity.outcome";

    /// <summary>
    /// The bounded reason an identity verification refused the caller, in lowercase snake case.
    /// </summary>
    public const string IdentityDenialReasonAttribute = "cratis.authproxy.identity.denial_reason";

    /// <summary>
    /// The result of an identity result-cache lookup: <c language="text">hit</c> or <c language="text">miss</c>.
    /// </summary>
    public const string IdentityCacheResultAttribute = "cratis.authproxy.identity.cache.result";

    /// <summary>
    /// The outcome of a bearer token validation, in lowercase snake case.
    /// </summary>
    public const string BearerOutcomeAttribute = "cratis.authproxy.bearer.outcome";

    /// <summary>
    /// The outcome of an invitation exchange, in lowercase snake case.
    /// </summary>
    public const string InviteOutcomeAttribute = "cratis.authproxy.invite.outcome";

    /// <summary>
    /// The outcome of a tenant resolution: <c language="text">resolved</c> or <c language="text">unresolved</c>.
    /// </summary>
    public const string TenantOutcomeAttribute = "cratis.authproxy.tenant.outcome";

    /// <summary>
    /// The kind of strategy that resolved the tenant, in lowercase snake case. Never the tenant identifier itself.
    /// </summary>
    public const string TenantStrategyAttribute = "cratis.authproxy.tenant.strategy";

    /// <summary>
    /// The standard OpenTelemetry attribute for the type of error, here the forwarder error in lowercase snake case.
    /// </summary>
    public const string ErrorTypeAttribute = "error.type";
}
