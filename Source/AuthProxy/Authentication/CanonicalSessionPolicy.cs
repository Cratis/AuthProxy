// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Decides whether an existing session cookie remains valid under the canonical identity rules.
/// </summary>
/// <remarks>
/// The policy only decides. Rejecting the principal and signing out stay with the authentication pipeline. Services
/// and options are read lazily, at the point each rule needs them.
/// </remarks>
static class CanonicalSessionPolicy
{
    /// <summary>
    /// Evaluates a session cookie.
    /// </summary>
    /// <param name="principal">The principal read from the cookie.</param>
    /// <param name="properties">The authentication properties read from the cookie.</param>
    /// <param name="schemeName">The name of the cookie authentication scheme.</param>
    /// <param name="services">The request services.</param>
    /// <returns>The <see cref="CanonicalSessionVerdict"/> for the session.</returns>
    internal static CanonicalSessionVerdict Evaluate(
        ClaimsPrincipal principal,
        AuthenticationProperties properties,
        string schemeName,
        IServiceProvider services)
    {
        var reservedClaims = principal.Claims.Where(_ => CanonicalIdentityClaims.IsReserved(_.Type)).ToArray();
        var fingerprintKeys = properties.Items.Keys
            .Where(_ => string.Equals(_, CanonicalSessionRegistrationFingerprint.StateKey, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (reservedClaims.Length == 0 && fingerprintKeys.Length == 0)
        {
            return EvaluateLegacy(properties, services);
        }

        if (reservedClaims.Length == 0)
        {
            return CanonicalSessionVerdict.MissingCanonicalClaims;
        }

        var stored = ReadStoredSession(properties, fingerprintKeys);
        if (stored is null)
        {
            return CanonicalSessionVerdict.MalformedRegistrationState;
        }

        try
        {
            return EvaluateRegistration(principal, schemeName, services, stored.Value);
        }
        catch (OptionsValidationException)
        {
            return CanonicalSessionVerdict.ConfigurationInvalid;
        }
    }

    /// <summary>
    /// Gets a value indicating whether a verdict accepts the session.
    /// </summary>
    /// <param name="verdict">The verdict to inspect.</param>
    /// <returns><see langword="true"/> when the session is accepted; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Acceptance of a legacy session does not end validation; the legacy session checks still run afterwards.
    /// </remarks>
    internal static bool Accepts(CanonicalSessionVerdict verdict) =>
        verdict is CanonicalSessionVerdict.Legacy or CanonicalSessionVerdict.Current;

    static CanonicalSessionVerdict EvaluateLegacy(AuthenticationProperties properties, IServiceProvider services)
    {
        try
        {
            var authentication = services
                .GetRequiredService<IOptionsMonitor<C.Authentication>>()
                .CurrentValue;
            if (!IsRecordedForCanonicalProvider(properties, authentication))
            {
                return CanonicalSessionVerdict.Legacy;
            }
        }
        catch (OptionsValidationException)
        {
            return CanonicalSessionVerdict.ConfigurationInvalid;
        }

        return CanonicalSessionVerdict.LegacySessionForCanonicalProvider;
    }

    static CanonicalSessionVerdict EvaluateRegistration(
        ClaimsPrincipal principal,
        string schemeName,
        IServiceProvider services,
        StoredSession stored)
    {
        var resolver = services.GetRequiredService<ICanonicalIdentityResolver>();
        var resolution = resolver.Resolve(principal, schemeName);
        if (!IsResolved(resolution))
        {
            return CanonicalSessionVerdict.UnresolvedIdentity;
        }

        return MatchesCurrentRegistration(services, stored)
            ? CanonicalSessionVerdict.Current
            : CanonicalSessionVerdict.RegistrationChanged;
    }

    static bool IsResolved(CanonicalIdentityResolution resolution) =>
        resolution.IsConfigured && resolution.Succeeded && resolution.Identity is not null;

    static bool MatchesCurrentRegistration(IServiceProvider services, StoredSession stored) =>
        TryCreateCurrentRegistrationFingerprint(services, stored.ProviderScheme, out var expectedFingerprint)
        && string.Equals(stored.Fingerprint, expectedFingerprint, StringComparison.Ordinal);

    static bool IsRecordedForCanonicalProvider(AuthenticationProperties properties, C.Authentication authentication)
    {
        if (!properties.Items.TryGetValue(AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey, out var scheme)
            || string.IsNullOrWhiteSpace(scheme))
        {
            return false;
        }

        return IsConfiguredCanonicalProvider(authentication, scheme);
    }

    static StoredSession? ReadStoredSession(AuthenticationProperties properties, string[] fingerprintKeys)
    {
        if (fingerprintKeys.Length != 1
            || !string.Equals(fingerprintKeys[0], CanonicalSessionRegistrationFingerprint.StateKey, StringComparison.Ordinal))
        {
            return null;
        }

        if (!properties.Items.TryGetValue(CanonicalSessionRegistrationFingerprint.StateKey, out var fingerprint)
            || !CanonicalSessionRegistrationFingerprint.IsWellFormed(fingerprint))
        {
            return null;
        }

        if (!properties.Items.TryGetValue(AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey, out var scheme)
            || string.IsNullOrWhiteSpace(scheme))
        {
            return null;
        }

        return new StoredSession(fingerprint!, scheme);
    }

    static bool IsConfiguredCanonicalProvider(C.Authentication authentication, string scheme) =>
        authentication.OidcProviders.Any(_ =>
            _.CanonicalIdentity is not null
            && string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal))
        || authentication.OAuthProviders.Any(_ =>
            _.CanonicalIdentity is not null
            && string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal));

    static bool TryCreateCurrentRegistrationFingerprint(IServiceProvider services, string scheme, out string fingerprint)
    {
        var authentication = services.GetRequiredService<IOptionsMonitor<C.Authentication>>().CurrentValue;
        var oidcProviders = authentication.OidcProviders
            .Where(_ => string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal))
            .ToArray();
        var oauthProviders = authentication.OAuthProviders
            .Where(_ => string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal))
            .ToArray();

        if (oidcProviders.Length + oauthProviders.Length != 1)
        {
            fingerprint = string.Empty;
            return false;
        }

        if (oidcProviders.Length == 1 && oidcProviders[0].CanonicalIdentity is not null)
        {
            var options = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme);
            fingerprint = CanonicalSessionRegistrationFingerprint.Create(scheme, oidcProviders[0], options);
            return true;
        }

        if (oauthProviders.Length == 1 && oauthProviders[0].CanonicalIdentity is not null)
        {
            var options = services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(scheme);
            fingerprint = CanonicalSessionRegistrationFingerprint.Create(scheme, oauthProviders[0], options);
            return true;
        }

        fingerprint = string.Empty;
        return false;
    }

    readonly record struct StoredSession(string Fingerprint, string ProviderScheme);
}
