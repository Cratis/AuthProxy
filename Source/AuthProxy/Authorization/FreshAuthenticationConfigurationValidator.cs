// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>Validates opt-in authentication-age rules at startup and on reload.</summary>
public class FreshAuthenticationConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();
        foreach (var (serviceName, service) in options.Services)
        {
            if (!service.FreshAuthenticationMethodOverrideUnsupported
                && service.FreshAuthentication?.Any(rule => rule?.Methods is { Count: > 0 }) == true)
            {
                failures.Add($"Service '{serviceName}' uses method-scoped fresh-authentication rules and must set FreshAuthenticationMethodOverrideUnsupported to true only when the backend does not support method overrides.");
            }
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var rule in service.FreshAuthentication ?? [])
            {
                if (rule is null || !FreshAuthenticationPolicy.TryNormalize(rule, out var path, out var methods)
                    || rule.MaxAge < TimeSpan.FromSeconds(1) || rule.MaxAge > TimeSpan.FromDays(1))
                {
                    failures.Add($"Service '{serviceName}' has an invalid fresh-authentication rule.");
                    continue;
                }
                var key = $"{path}|{rule.Prefix}|{string.Join(',', methods.Order(StringComparer.OrdinalIgnoreCase))}";
                if (!seen.Add(key))
                {
                    failures.Add($"Service '{serviceName}' has a duplicate fresh-authentication rule.");
                }
            }
        }
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
