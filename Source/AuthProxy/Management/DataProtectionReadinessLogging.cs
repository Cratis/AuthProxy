// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management;

internal static partial class DataProtectionReadinessLogging
{
    [LoggerMessage(LogLevel.Warning, "The Data Protection key ring could not be initialized, so this instance cannot serve an authenticated request and reports itself as not ready. Check that the configured Data Protection key store (DataProtectionKeysPath, Azure Blob Storage or Redis, and the Key Vault key if set) is reachable and accessible by the process.")]
    internal static partial void KeyRingUnavailable(this ILogger<DataProtectionReadiness> logger, Exception exception);
}
