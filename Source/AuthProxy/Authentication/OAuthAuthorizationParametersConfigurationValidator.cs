// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates additional OAuth authorization-request parameters against the parameters owned by the framework.
/// </summary>
sealed class OAuthAuthorizationParametersConfigurationValidator : IValidateOptions<C.Authentication>
{
    static readonly HashSet<string> _frameworkOwnedParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "client_id",
        "scope",
        "response_type",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method"
    };

    /// <summary>
    /// Validates that configured authorization parameters cannot replace framework-generated protocol values.
    /// </summary>
    /// <param name="name">The options instance name. Validation applies identically to every name.</param>
    /// <param name="options">The authentication provider configuration to validate.</param>
    /// <returns>A successful result when no configured parameter is framework-owned; otherwise, all collisions.</returns>
    public ValidateOptionsResult Validate(string? name, C.Authentication options)
    {
        var failures = options.OAuthProviders
            .SelectMany(provider => provider.AuthorizationParameters.Keys
                .Where(_frameworkOwnedParameters.Contains)
                .Select(parameter => $"OAuth provider '{provider.Name}' cannot configure framework-owned authorization parameter '{parameter}'."))
            .ToArray();

        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
