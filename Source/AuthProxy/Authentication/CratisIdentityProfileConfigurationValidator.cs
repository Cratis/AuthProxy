// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Refuses to start with a Cratis Identity provider that lacks an absolute authority, uses a non-HTTPS authority outside
/// the <see cref="C.DeploymentProfile.LocalDevelopment"/> profile, or has no client credentials.
/// </summary>
public sealed class CratisIdentityProfileConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = options.Authentication.OidcProviders
            .Where(CratisIdentityProfile.AppliesTo)
            .SelectMany(provider => Problems(provider, options.Profile).Select(problem => $"Cratis Identity provider '{provider.Name}': {problem}"))
            .ToArray();

        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static IEnumerable<string> Problems(C.OidcProvider provider, C.DeploymentProfile profile)
    {
        if (AuthorityProblem(provider.Authority, profile) is { } authorityProblem)
        {
            yield return authorityProblem;
        }

        if (string.IsNullOrWhiteSpace(provider.ClientId))
        {
            yield return "ClientId is required.";
        }

        if (string.IsNullOrWhiteSpace(provider.ClientSecret) && !provider.UsesClientAssertion)
        {
            yield return "A confidential client is required: configure ClientSecret or a certificate or federated ClientCredential.";
        }
    }

    static string? AuthorityProblem(string value, C.DeploymentProfile profile)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var authority) || HasExtras(authority))
        {
            return "Authority must be an absolute URL without user information, query, or fragment.";
        }

        var allowed = authority.Scheme == Uri.UriSchemeHttps
            || (authority.Scheme == Uri.UriSchemeHttp && profile == C.DeploymentProfile.LocalDevelopment);
        return allowed ? null : "Authority must use HTTPS; HTTP is allowed only in the LocalDevelopment profile.";
    }

    static bool HasExtras(Uri authority) =>
        authority.UserInfo.Length > 0 || authority.Query.Length > 0 || authority.Fragment.Length > 0;
}
