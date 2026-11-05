// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>Shares the v1 verifier-backed deployment across transport specs.</summary>
[CollectionDefinition(Name)]
public class ForwardedIdentitySpecCollection : ICollectionFixture<ForwardedIdentityHarness>
{
    /// <summary>The collection name.</summary>
    public const string Name = "Forwarded identity v1";
}
