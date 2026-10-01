// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

internal static partial class IdentityVerificationLogging
{
    [LoggerMessage(LogLevel.Warning, "Required identity verification for service '{Service}' denied the request: {Reason}. To keep the previous enrichment-only behavior, set IdentityVerification to BestEffort for this service: Cratis__AuthProxy__Services__{Service}__IdentityVerification=BestEffort")]
    internal static partial void RequiredIdentityVerificationDenied(this ILogger logger, string service, string reason);

    /// <summary>
    /// Logs one denial with the compatibility opt-outs for every Required service.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="services">The configured names of the Required services.</param>
    /// <param name="reason">The bounded reason for the denial.</param>
    internal static void RequiredIdentityResolutionDenied(this ILogger logger, IEnumerable<string> services, string reason)
    {
        var names = services.ToArray();
        logger.RequiredIdentityResolutionDenied(
            string.Join(", ", names),
            reason,
            string.Join("; ", names.Select(name => $"Cratis__AuthProxy__Services__{name}__IdentityVerification=BestEffort")));
    }

    [LoggerMessage(LogLevel.Debug, "Identity verification for service '{Service}' denied the request: Canceled")]
    internal static partial void IdentityVerificationCanceled(this ILogger logger, string service);

    [LoggerMessage(LogLevel.Warning, "Required identity resolution for services '{Services}' denied the request: {Reason}. To keep the previous enrichment-only behavior, set IdentityVerification to BestEffort for these services: {OptOuts}")]
    static partial void RequiredIdentityResolutionDenied(this ILogger logger, string services, string reason, string optOuts);
}
