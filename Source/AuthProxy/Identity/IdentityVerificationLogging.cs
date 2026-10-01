// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

internal static partial class IdentityVerificationLogging
{
    [LoggerMessage(LogLevel.Warning, "Required identity verification for service '{Service}' denied the request: {Reason}. To keep the previous enrichment-only behavior, set IdentityVerification to BestEffort for this service: Cratis__AuthProxy__Services__{Service}__IdentityVerification=BestEffort")]
    internal static partial void RequiredIdentityVerificationDenied(this ILogger logger, string service, string reason);
}
