// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Refuses a configuration whose client-credentials refresh token family lifetime is not positive.
/// </summary>
public class ClientCredentialsConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = options.Services
            .Where(_ => _.Value.ClientCredentials is { } credentials && credentials.RefreshTokenFamilyLifetime <= TimeSpan.Zero)
            .Select(_ => $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Services)}:{_.Key}:{nameof(C.Service.ClientCredentials)}:{nameof(C.ServiceClientCredentials.RefreshTokenFamilyLifetime)} is '{_.Value.ClientCredentials!.RefreshTokenFamilyLifetime}', which is not greater than zero. State how long a chain of refreshed tokens may be used, for example '30.00:00:00', or leave the setting unset for the default of {ClientCredentialsDefaults.DefaultRefreshTokenFamilyLifetime}.")
            .ToList();

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
