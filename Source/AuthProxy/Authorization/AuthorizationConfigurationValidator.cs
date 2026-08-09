// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>
/// Refuses a configuration declaring a claim requirement that names no claim.
/// </summary>
/// <remarks>
/// Such a requirement can never be satisfied, so the proxy would start and then refuse every single
/// caller — an outage whose cause is a blank value in an environment variable and whose symptom is a
/// <c>403</c> page saying nothing about it. Failing at startup names it instead, at the one moment
/// somebody is watching.
/// <para>
/// The alternative — dropping the malformed requirement — is the one thing that must not happen: a
/// requirement that is silently not applied is a gate that is silently open, which is the failure mode
/// this whole feature exists to close.
/// </para>
/// </remarks>
public class AuthorizationConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();

        AddFailureForBlankClaims(options.Authorization, "Cratis:AuthProxy:Authorization", failures);

        foreach (var (key, service) in options.Services)
        {
            AddFailureForBlankClaims(service.Authorization, $"Cratis:AuthProxy:Services:{key}:Authorization", failures);
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }

    static void AddFailureForBlankClaims(C.Authorization? authorization, string section, List<string> failures)
    {
        if (authorization is null)
        {
            return;
        }

        for (var index = 0; index < authorization.RequiredClaims.Count; index++)
        {
            if (string.IsNullOrWhiteSpace(authorization.RequiredClaims[index].Claim))
            {
                failures.Add($"{section}:RequiredClaims:{index}:Claim must name a claim type. A requirement without one can never be satisfied and would refuse every caller.");
            }
        }
    }
}
