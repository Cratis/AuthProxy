// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Refuses unusable signing settings before serving traffic.</summary>
public sealed class ForwardedIdentitySigningConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();
        foreach (var (serviceName, service) in options.Services)
        {
            Validate(service.ForwardedIdentity, $"{C.AuthProxy.SectionKey}:Services:{serviceName}", failures);
        }
        if (TenantSelectionMiddleware.TryGetSelectionOptions(options, out var selection))
        {
            var resolution = options.TenantResolutions.First(resolution => resolution.Strategy == C.TenantSourceIdentifierResolverType.Selection);
            var index = options.TenantResolutions.IndexOf(resolution);
            Validate(selection.ForwardedIdentity, $"{C.AuthProxy.SectionKey}:TenantResolutions:{index}:Options", failures);
        }
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void Validate(C.ForwardedIdentitySigning? settings, string path, List<string> failures)
    {
        if (settings is not null && !ForwardedIdentitySigningKey.TryCreate(settings, out _, out var problem))
        {
            failures.Add($"{path}:{problem}");
        }
    }
}
