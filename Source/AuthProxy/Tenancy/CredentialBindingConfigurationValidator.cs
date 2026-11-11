// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>Validates the trusted deployment identifiers used to bind credentials.</summary>
public sealed class CredentialBindingConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        List<string> failures = [];
        ValidateIdentifier(nameof(C.CredentialBinding.Resource), options.CredentialBinding.Resource, failures);
        ValidateIdentifier(nameof(C.CredentialBinding.Environment), options.CredentialBinding.Environment, failures);
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateIdentifier(string key, string value, List<string> failures)
    {
        if (value.Length > 0 && !TenantIdentifier.IsUsable(value))
        {
            failures.Add($"{C.AuthProxy.SectionKey}:CredentialBinding:{key} must contain only letters, digits, '-', '.', '_' or '~', with at most 256 characters and no surrounding whitespace.");
        }
    }
}
