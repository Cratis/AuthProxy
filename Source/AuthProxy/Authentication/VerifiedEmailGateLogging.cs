// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Holds the log messages for <see cref="VerifiedEmailGate"/>.
/// </summary>
internal static partial class VerifiedEmailGateLogging
{
    /// <summary>
    /// Logs that a provider callback was refused because it did not carry exactly one verified e-mail address.
    /// </summary>
    /// <param name="logger">The logger to write to.</param>
    /// <param name="scheme">The authentication scheme of the provider.</param>
    [LoggerMessage(LogLevel.Warning, "Sign-in through provider scheme '{Scheme}' was refused because the principal does not carry exactly one verified e-mail address.")]
    internal static partial void VerifiedEmailRequired(this ILogger logger, string scheme);
}
