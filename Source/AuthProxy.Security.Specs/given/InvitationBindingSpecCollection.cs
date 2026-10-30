// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Shares one <see cref="InvitationBindingHarness"/> across the invitation binding specs.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class InvitationBindingSpecCollection : ICollectionFixture<InvitationBindingHarness>
{
    /// <summary>The collection name every invitation binding spec joins.</summary>
    public const string Name = "InvitationBinding";
}
