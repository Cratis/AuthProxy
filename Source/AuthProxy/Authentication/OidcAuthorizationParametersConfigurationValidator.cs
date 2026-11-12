// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates the OIDC provider settings that gate weaker providers: authorization parameters and the denial response.
/// </summary>
sealed class OidcAuthorizationParametersConfigurationValidator : IValidateOptions<C.Authentication>
{
    static readonly HashSet<string> _frameworkOwnedParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "client_id",
        "scope",
        "response_type",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "response_mode",
        "request",
        "request_uri",
        "max_age",
        "id_token_hint",
        "client_assertion",
        "client_assertion_type"
    };

    /// <summary>
    /// Validates the configured authorization parameters and denial response of every OIDC provider.
    /// </summary>
    /// <param name="name">The options instance name. Validation applies identically to every name.</param>
    /// <param name="options">The authentication provider configuration to validate.</param>
    /// <returns>A successful result when every provider is valid; otherwise, all failures.</returns>
    public ValidateOptionsResult Validate(string? name, C.Authentication options)
    {
        var failures = options.OidcProviders
            .SelectMany(Failures)
            .ToArray();

        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static IEnumerable<string> Failures(C.OidcProvider provider) =>
        DenialResponseFailures(provider)
            .Concat(provider.AuthorizationParameters.SelectMany(parameter => ParameterFailures(provider, parameter)))
            .Concat(CaseCollisionFailures(provider));

    static IEnumerable<string> DenialResponseFailures(C.OidcProvider provider) =>
        Enum.IsDefined(provider.DenialResponse)
            ? []
            : [$"OIDC provider '{provider.Name}' has an unsupported DenialResponse '{provider.DenialResponse}'."];

    static IEnumerable<string> ParameterFailures(C.OidcProvider provider, KeyValuePair<string, string> parameter)
    {
        if (string.IsNullOrWhiteSpace(parameter.Key))
        {
            return [$"OIDC provider '{provider.Name}' cannot configure an authorization parameter with a blank name."];
        }

        if (_frameworkOwnedParameters.Contains(parameter.Key))
        {
            return [$"OIDC provider '{provider.Name}' cannot configure framework-owned authorization parameter '{parameter.Key}'."];
        }

        return string.IsNullOrWhiteSpace(parameter.Value)
            ? [$"OIDC provider '{provider.Name}' authorization parameter '{parameter.Key}' must have a value."]
            : [];
    }

    static IEnumerable<string> CaseCollisionFailures(C.OidcProvider provider) =>
        provider.AuthorizationParameters.Keys
            .Where(_ => !string.IsNullOrWhiteSpace(_))
            .GroupBy(_ => _, StringComparer.OrdinalIgnoreCase)
            .Where(_ => _.Count() > 1)
            .Select(_ => $"OIDC provider '{provider.Name}' configures authorization parameter '{_.Key}' more than once with different casing.");
}
