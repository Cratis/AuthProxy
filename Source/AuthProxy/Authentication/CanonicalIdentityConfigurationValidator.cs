// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates canonical identity configuration across all registered OIDC and OAuth providers.
/// </summary>
/// <remarks>
/// Validation enforces an unambiguous provider scheme and provider key, exact subject-claim selection, and the issuer
/// source appropriate to each protocol. It validates configuration only; it does not authenticate a principal.
/// </remarks>
sealed class CanonicalIdentityConfigurationValidator : IValidateOptions<C.Authentication>
{
    /// <summary>
    /// Validates the canonical identity contracts in the supplied authentication options.
    /// </summary>
    /// <param name="name">The options instance name. Canonical identity validation applies identically to every name.</param>
    /// <param name="options">The authentication provider configuration to validate.</param>
    /// <returns>A successful result when every canonical contract is valid; otherwise, all detected configuration failures.</returns>
    public ValidateOptionsResult Validate(string? name, C.Authentication options)
    {
        var failures = new List<string>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var schemes = options.OidcProviders.Select(_ => OidcProviderScheme.FromName(_.Name))
            .Concat(options.OAuthProviders.Select(_ => OidcProviderScheme.FromName(_.Name)))
            .GroupBy(_ => _, StringComparer.Ordinal)
            .ToDictionary(_ => _.Key, _ => _.Count(), StringComparer.Ordinal);

        foreach (var provider in options.OidcProviders)
        {
            ValidateScheme(provider.Name, provider.CanonicalIdentity, schemes, failures);
            ValidateIdentity(provider.CanonicalIdentity, true, keys, failures);
        }

        foreach (var provider in options.OAuthProviders)
        {
            ValidateScheme(provider.Name, provider.CanonicalIdentity, schemes, failures);
            ValidateIdentity(provider.CanonicalIdentity, false, keys, failures);
            if (!string.IsNullOrWhiteSpace(provider.VerifiedEmailEndpoint)
                && (!Uri.TryCreate(provider.VerifiedEmailEndpoint, UriKind.Absolute, out var endpoint)
                    || (!string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                        && !(string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && endpoint.IsLoopback))
                    || !string.IsNullOrEmpty(endpoint.UserInfo)
                    || !string.IsNullOrEmpty(endpoint.Fragment)))
            {
                failures.Add("OAuth verified-email endpoints must be absolute HTTPS URLs, except for loopback development endpoints.");
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateScheme(
        string name,
        C.CanonicalIdentity? identity,
        Dictionary<string, int> schemes,
        List<string> failures)
    {
        if (identity is not null && schemes[OidcProviderScheme.FromName(name)] != 1)
        {
            failures.Add("Authentication provider names must produce distinct schemes.");
        }
    }

    static void ValidateIdentity(C.CanonicalIdentity? identity, bool isOidc, HashSet<string> keys, List<string> failures)
    {
        if (identity is null)
        {
            return;
        }

        if (identity.ProviderKey.Length is < 1 or > 64
            || identity.ProviderKey[0] is not ((>= 'a' and <= 'z') or (>= '0' and <= '9'))
            || identity.ProviderKey.Any(character => !(character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-'))
            || !keys.Add(identity.ProviderKey))
        {
            failures.Add("Canonical provider keys must be unique, lowercase, bounded ASCII identifiers.");
        }

        if (string.IsNullOrWhiteSpace(identity.SubjectClaimType)
            || !string.Equals(identity.SubjectClaimType, identity.SubjectClaimType.Trim(), StringComparison.Ordinal)
            || identity.SubjectClaimType.Length > 256
            || CanonicalIdentityClaims.IsReserved(identity.SubjectClaimType))
        {
            failures.Add("Canonical subject claim types must be nonempty, bounded, and outside the reserved Cratis namespace.");
        }

        var evidenceClaimTypes = new[]
        {
            identity.SubjectClaimType,
            identity.EmailClaimType,
            identity.EmailVerifiedClaimType,
            identity.AssuranceClaimType,
        };
        if (evidenceClaimTypes.Any(_ =>
                string.IsNullOrWhiteSpace(_)
                || !string.Equals(_, _.Trim(), StringComparison.Ordinal)
                || _.Length > 256
                || _.Any(char.IsControl)
                || CanonicalIdentityClaims.IsReserved(_))
            || evidenceClaimTypes.Distinct(StringComparer.Ordinal).Count() != evidenceClaimTypes.Length)
        {
            failures.Add("Canonical subject, email, email-verification, and assurance claim types must be distinct, nonempty, bounded, and outside the reserved Cratis namespace.");
        }

        if (isOidc && identity.Issuer is not null)
        {
            failures.Add("Canonical OIDC providers obtain the issuer from the framework-validated token and cannot configure a literal issuer.");
        }

        if (!isOidc && !CanonicalIssuer.TryNormalize(identity.Issuer, out _))
        {
            failures.Add("Canonical OAuth providers require an absolute normalized HTTPS issuer, except for loopback development issuers.");
        }
    }
}
