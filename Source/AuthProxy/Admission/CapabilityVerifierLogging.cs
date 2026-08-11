// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Holds the log messages for <see cref="CapabilityVerifier"/>.
/// </summary>
/// <remarks>
/// Deliberately parameterless. A capability is a bearer value and the path it is presented on names the
/// deployment's closed door, so neither may reach a log sink — an operator reading logs is not the only
/// party who ever reads them.
/// </remarks>
internal static partial class CapabilityVerifierLogging
{
    [LoggerMessage(LogLevel.Debug, "A presented capability was refused by the verifier.")]
    internal static partial void CapabilityRefused(this ILogger<CapabilityVerifier> logger);

    [LoggerMessage(LogLevel.Warning, "The capability verifier could not be reached, or did not answer in time. Every presentation is refused while this holds.")]
    internal static partial void CapabilityVerifierUnavailable(this ILogger<CapabilityVerifier> logger);

    [LoggerMessage(LogLevel.Warning, "The capability verifier answered about a different presentation than the one it was asked about.")]
    internal static partial void CapabilityVerifierAnsweredAnotherPresentation(this ILogger<CapabilityVerifier> logger);

    [LoggerMessage(LogLevel.Error, "No capability verifier is configured, so nothing can be admitted.")]
    internal static partial void CapabilityVerifierNotConfigured(this ILogger<CapabilityVerifier> logger);
}
