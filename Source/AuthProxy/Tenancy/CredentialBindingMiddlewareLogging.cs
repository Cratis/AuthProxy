// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

internal static partial class CredentialBindingMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Refused a {CredentialKind} credential bound to another tenant for {Path}")]
    internal static partial void CredentialBoundToAnotherTenant(this ILogger logger, string credentialKind, string path);
}
