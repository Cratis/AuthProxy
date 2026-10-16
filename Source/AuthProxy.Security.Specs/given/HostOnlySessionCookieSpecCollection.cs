// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares one <see cref="HostOnlySessionCookieHarness"/> across the specs that guard the default behavior.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class HostOnlySessionCookieSpecCollection : ICollectionFixture<HostOnlySessionCookieHarness>
{
    /// <summary>The collection name every host-only session cookie spec joins.</summary>
    public const string Name = "HostOnlySessionCookie";
}
