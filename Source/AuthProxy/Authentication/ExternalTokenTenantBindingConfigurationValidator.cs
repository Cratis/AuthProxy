// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Tenancy;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Validates the opt-in contract for general JWT tenant binding.</summary>
/// <param name="configuration">The deployment configuration.</param>
sealed class ExternalTokenTenantBindingConfigurationValidator(IConfiguration configuration) : IValidateOptions<C.Authentication>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.Authentication options)
    {
        var settings = options.ExternalTokenTenantBinding;
        if (!settings.Require) return ValidateOptionsResult.Success;

        var failures = new List<string>();
        if (!configuration.GetSection($"{C.Authentication.SectionKey}:JwtBearer").Exists())
        {
            failures.Add("External token tenant binding requires a configured JWT Bearer handler.");
        }

        if (string.IsNullOrWhiteSpace(settings.TenantClaimType))
        {
            failures.Add("External token tenant binding requires a tenant claim type.");
        }

        if (settings.TenantMapping.Values.Any(_ => !TenantIdentifier.IsUsable(_)))
        {
            failures.Add("External token tenant mappings must name usable AuthProxy tenant identifiers.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
