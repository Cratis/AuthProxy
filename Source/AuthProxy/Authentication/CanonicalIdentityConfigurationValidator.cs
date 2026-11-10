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
        List<string> failures = [];
        HashSet<string> keys = [with(StringComparer.Ordinal)];
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
            ValidateVerifiedEmailEndpoint(provider.VerifiedEmailEndpoint, failures);
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

        if (!IsValidProviderKey(identity.ProviderKey) || !keys.Add(identity.ProviderKey))
        {
            failures.Add("Canonical provider keys must be unique, lowercase, bounded ASCII identifiers.");
        }

        if (!HasValidClaimTypeShape(identity.SubjectClaimType) || CanonicalIdentityClaims.IsReserved(identity.SubjectClaimType))
        {
            failures.Add("Canonical subject claim types must be nonempty, bounded, and outside the reserved Cratis namespace.");
        }

        ValidateEvidenceClaimTypes(identity, failures);
        ValidateIssuer(identity, isOidc, failures);
    }

    static void ValidateEvidenceClaimTypes(C.CanonicalIdentity identity, List<string> failures)
    {
        var evidenceClaimTypes = new[]
        {
            identity.SubjectClaimType,
            identity.EmailClaimType,
            identity.EmailVerifiedClaimType,
            identity.AssuranceClaimType,
        };
        if (evidenceClaimTypes.Any(_ =>
                !HasValidClaimTypeShape(_)
                || _.Any(char.IsControl)
                || CanonicalIdentityClaims.IsReserved(_))
            || evidenceClaimTypes.Distinct(StringComparer.Ordinal).Count() != evidenceClaimTypes.Length)
        {
            failures.Add("Canonical subject, email, email-verification, and assurance claim types must be distinct, nonempty, bounded, and outside the reserved Cratis namespace.");
        }
    }

    static void ValidateIssuer(C.CanonicalIdentity identity, bool isOidc, List<string> failures)
    {
        if (isOidc && identity.Issuer is not null)
        {
            failures.Add("Canonical OIDC providers obtain the issuer from the framework-validated token and cannot configure a literal issuer.");
        }

        if (!isOidc && !CanonicalIssuer.TryNormalize(identity.Issuer, out _))
        {
            failures.Add("Canonical OAuth providers require an absolute normalized HTTPS issuer, except for loopback development issuers.");
        }
    }

    static bool IsValidProviderKey(string key)
    {
        if (key.Length is < 1 or > 64)
        {
            return false;
        }

        return (key[0] is (>= 'a' and <= 'z') or (>= '0' and <= '9'))
            && key.All(character => character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '_' or '-');
    }

    static bool HasValidClaimTypeShape(string claimType) =>
        !string.IsNullOrWhiteSpace(claimType)
        && string.Equals(claimType, claimType.Trim(), StringComparison.Ordinal)
        && claimType.Length <= 256;

    static void ValidateVerifiedEmailEndpoint(string endpoint, List<string> failures)
    {
        if (!string.IsNullOrWhiteSpace(endpoint) && !IsValidVerifiedEmailEndpoint(endpoint))
        {
            failures.Add("OAuth verified-email endpoints must be absolute HTTPS URLs, except for loopback development endpoints.");
        }
    }

    static bool IsValidVerifiedEmailEndpoint(string candidate)
    {
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var endpoint))
        {
            return false;
        }

        if (!IsPermittedEndpointScheme(endpoint))
        {
            return false;
        }

        return string.IsNullOrEmpty(endpoint.UserInfo) && string.IsNullOrEmpty(endpoint.Fragment);
    }

    static bool IsPermittedEndpointScheme(Uri endpoint) =>
        string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
        || (string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && endpoint.IsLoopback);
}
