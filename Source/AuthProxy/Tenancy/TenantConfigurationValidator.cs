// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Validates the source identifiers and domains configured for tenant resolution.
/// </summary>
public sealed class TenantConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        List<string> failures = [];
        foreach (var (tenantId, tenant) in options.Tenants)
        {
            ValidateEntries(tenantId, nameof(C.Tenant.SourceIdentifiers), tenant.SourceIdentifiers, failures);
            ValidateEntries(tenantId, nameof(C.Tenant.Domains), tenant.Domains, failures);
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateEntries(string tenantId, string listName, IEnumerable<string> entries, List<string> failures)
    {
        if (entries.Any(string.IsNullOrWhiteSpace))
        {
            failures.Add($"{C.AuthProxy.SectionKey}:Tenants:{tenantId}:{listName} must not contain empty or whitespace-only entries.");
        }
    }
}
