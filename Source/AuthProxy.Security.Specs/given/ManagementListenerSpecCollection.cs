// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the management-listener specs against one pair of real proxies and one origin, in sequence.
/// </summary>
/// <remarks>
/// The origin records what it received, and these specs read that record to decide whether anything got
/// past the private listener. Two specs running concurrently would read each other's traffic — and so would
/// the count of outbound clients — so the collection serializes them, and starts the two hosts once rather
/// than per spec class.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class ManagementListenerSpecCollection : ICollectionFixture<ManagementListenerHarness>
{
    /// <summary>The collection name every management-listener spec joins.</summary>
    public const string Name = "ManagementListener";
}
