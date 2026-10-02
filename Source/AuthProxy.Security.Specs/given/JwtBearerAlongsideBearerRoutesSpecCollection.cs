// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs every spec against the deployment where the JWT Bearer handler trusts a bearer-route issuer, in sequence.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class JwtBearerAlongsideBearerRoutesSpecCollection : ICollectionFixture<JwtBearerAlongsideBearerRoutesHarness>
{
    /// <summary>The collection name every spec against that deployment joins.</summary>
    public const string Name = "JwtBearerAlongsideBearerRoutes";
}
