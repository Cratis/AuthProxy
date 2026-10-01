// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Identifies the participating services whose positive verdicts are required to authorize a caller.
/// </summary>
internal static class IdentityVerificationServices
{
    /// <summary>
    /// Gets the Required services in a stable order for authorization records and result-cache keys.
    /// </summary>
    /// <param name="configuration">The configuration being resolved against.</param>
    /// <returns>The sorted configured service names.</returns>
    internal static string[] Required(C.AuthProxy configuration) => configuration.Services
        .Where(_ => _.Value.ParticipatesInIdentityResolution && _.Value.IdentityVerification == C.IdentityVerificationMode.Required)
        .Select(_ => _.Key)
        .Order(StringComparer.Ordinal)
        .ToArray();
}
