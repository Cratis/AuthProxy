// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management;

internal static partial class DataProtectionReadinessLogging
{
    [LoggerMessage(LogLevel.Warning, "The Data Protection key ring could not be initialized, so this instance cannot serve an authenticated request and reports itself as not ready. Check that the configured DataProtectionKeysPath exists and is writable by the process.")]
    internal static partial void KeyRingUnavailable(this ILogger<DataProtectionReadiness> logger, Exception exception);
}
