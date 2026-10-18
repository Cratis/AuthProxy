// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the signed bearer-route specs against one shared proxy, origin and issuer, in sequence.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class SignedBearerRouteSpecCollection : ICollectionFixture<SignedBearerRouteHarness>
{
    /// <summary>The collection name every signed bearer-route spec joins.</summary>
    public const string Name = "SignedBearerRoutes";
}
