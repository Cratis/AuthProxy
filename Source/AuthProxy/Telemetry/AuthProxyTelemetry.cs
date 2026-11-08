// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;
using System.Text;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Telemetry;

/// <summary>
/// The single place AuthProxy creates its spans and records its metrics.
/// </summary>
/// <remarks>
/// Every attribute is a member of a closed enumeration written in lowercase snake case. Nothing a caller
/// controls — a token, a claim value, a subject, an email, a cookie, a URL or a tenant identifier — can reach
/// this class, because no method accepts one: the only inputs are enumerations the proxy itself defines.
/// </remarks>
static class AuthProxyTelemetry
{
    static readonly string _version = ReadVersion();
    static readonly ActivitySource _activitySource = new(WellKnownTelemetryNames.Scope, _version);
    static readonly Meter _meter = new(WellKnownTelemetryNames.Scope, _version);

    static readonly Counter<long> _signIns = _meter.CreateCounter<long>(
        WellKnownTelemetryNames.SignInsMetric,
        unit: "{sign_in}",
        description: "Completed sign-ins, by the outcome of notifying the application.");

    static readonly Counter<long> _identityDenials = _meter.CreateCounter<long>(
        WellKnownTelemetryNames.IdentityDenialsMetric,
        unit: "{denial}",
        description: "Identity verifications that refused the caller, by the bounded reason.");

    static readonly Counter<long> _identityCacheRequests = _meter.CreateCounter<long>(
        WellKnownTelemetryNames.IdentityCacheRequestsMetric,
        unit: "{request}",
        description: "Lookups of an already resolved identity, by whether one was found.");

    static readonly Counter<long> _bearerValidations = _meter.CreateCounter<long>(
        WellKnownTelemetryNames.BearerValidationsMetric,
        unit: "{validation}",
        description: "Validations of the access token presented on a bearer route, by outcome.");

    static readonly Counter<long> _inviteExchanges = _meter.CreateCounter<long>(
        WellKnownTelemetryNames.InviteExchangesMetric,
        unit: "{exchange}",
        description: "Exchanges of an invitation for a completed sign-in, by outcome.");

    static readonly Counter<long> _upstreamErrors = _meter.CreateCounter<long>(
        WellKnownTelemetryNames.UpstreamErrorsMetric,
        unit: "{error}",
        description: "Requests that could not be forwarded to a service, by error type.");

    /// <summary>
    /// Starts an internal span in the AuthProxy scope.
    /// </summary>
    /// <param name="name">One of the span names in <see cref="WellKnownTelemetryNames"/>.</param>
    /// <returns>The activity, or <see langword="null"/> when nothing is listening.</returns>
    public static Activity? Start(string name) => _activitySource.StartActivity(name, ActivityKind.Internal);

    /// <summary>
    /// Records the outcome of notifying the application of a sign-in.
    /// </summary>
    /// <param name="activity">The span to tag.</param>
    /// <param name="outcome">The outcome.</param>
    public static void SignInNotified(Activity? activity, Enum outcome)
    {
        var value = Name(outcome);
        activity?.SetTag(WellKnownTelemetryNames.SignInOutcomeAttribute, value);
        _signIns.Add(1, new KeyValuePair<string, object?>(WellKnownTelemetryNames.SignInOutcomeAttribute, value));
    }

    /// <summary>
    /// Records the outcome of validating a bearer token.
    /// </summary>
    /// <param name="activity">The span to tag.</param>
    /// <param name="outcome">The outcome.</param>
    public static void BearerValidated(Activity? activity, Enum outcome)
    {
        var value = Name(outcome);
        activity?.SetTag(WellKnownTelemetryNames.BearerOutcomeAttribute, value);
        _bearerValidations.Add(1, new KeyValuePair<string, object?>(WellKnownTelemetryNames.BearerOutcomeAttribute, value));
    }

    /// <summary>
    /// Runs an invitation exchange inside its span and records its outcome.
    /// </summary>
    /// <param name="exchange">The exchange to run.</param>
    /// <returns>The outcome of the exchange.</returns>
    public static async Task<InviteExchangeResult> TraceInviteExchange(Func<Task<InviteExchangeResult>> exchange)
    {
        using var activity = Start(WellKnownTelemetryNames.InviteExchangeSpan);
        var result = await exchange();
        var value = Name(result);
        activity?.SetTag(WellKnownTelemetryNames.InviteOutcomeAttribute, value);
        _inviteExchanges.Add(1, new KeyValuePair<string, object?>(WellKnownTelemetryNames.InviteOutcomeAttribute, value));
        return result;
    }

    /// <summary>
    /// Records the outcome of resolving the tenant of a request.
    /// </summary>
    /// <param name="activity">The span to tag.</param>
    /// <param name="resolved">Whether a tenant was resolved.</param>
    /// <param name="strategy">The kind of strategy that resolved it.</param>
    public static void TenantResolved(Activity? activity, bool resolved, Enum strategy)
    {
        activity?.SetTag(WellKnownTelemetryNames.TenantOutcomeAttribute, resolved ? "resolved" : "unresolved");
        activity?.SetTag(WellKnownTelemetryNames.TenantStrategyAttribute, Name(strategy));
    }

    /// <summary>
    /// Records the outcome of resolving the identity details of a caller.
    /// </summary>
    /// <param name="activity">The span to tag.</param>
    /// <param name="authorized">Whether the caller was authorized.</param>
    public static void IdentityResolved(Activity? activity, bool authorized) =>
        activity?.SetTag(WellKnownTelemetryNames.IdentityOutcomeAttribute, authorized ? "authorized" : "denied");

    /// <summary>
    /// Records an identity verification that refused the caller.
    /// </summary>
    /// <param name="reason">The bounded reason.</param>
    public static void IdentityDenied(Enum reason) =>
        _identityDenials.Add(1, new KeyValuePair<string, object?>(WellKnownTelemetryNames.IdentityDenialReasonAttribute, Name(reason)));

    /// <summary>
    /// Records a lookup of an already resolved identity.
    /// </summary>
    /// <param name="hit">Whether one was found.</param>
    public static void IdentityCacheLookup(bool hit) =>
        _identityCacheRequests.Add(1, new KeyValuePair<string, object?>(WellKnownTelemetryNames.IdentityCacheResultAttribute, hit ? "hit" : "miss"));

    /// <summary>
    /// Records a request that could not be forwarded to a service.
    /// </summary>
    /// <param name="error">The forwarder error.</param>
    public static void UpstreamFailed(Enum error) =>
        _upstreamErrors.Add(1, new KeyValuePair<string, object?>(WellKnownTelemetryNames.ErrorTypeAttribute, Name(error)));

    static string Name(Enum value) => EnumNames.GetOrAdd(value, ToSnakeCase);

    static string ToSnakeCase(Enum value)
    {
        var name = value.ToString();
        var builder = new StringBuilder(name.Length + 4);
        for (var index = 0; index < name.Length; index++)
        {
            if (char.IsUpper(name[index]) && index > 0)
            {
                builder.Append('_');
            }

            builder.Append(char.ToLowerInvariant(name[index]));
        }

        return builder.ToString();
    }

    static string ReadVersion()
    {
        var informational = typeof(AuthProxyTelemetry).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return informational?.Split('+')[0] ?? "0.0.0";
    }

    /// <summary>
    /// Enumerations are a closed set, so this table is bounded by the enumerations the proxy defines.
    /// </summary>
    static class EnumNames
    {
        static readonly ConcurrentDictionary<Enum, string> _names = new();

        public static string GetOrAdd(Enum value, Func<Enum, string> create) => _names.GetOrAdd(value, create);
    }
}
