// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the required-verification specs against one shared proxy and origin, in sequence.
/// </summary>
/// <remarks>
/// Separate from the other collections because it is a different deployment, with its own origin recording
/// its own traffic. Serialized for the same reason they are, and for one more: these specs change what the
/// origin answers, so two of them running at once would be answering each other's questions.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class RequiredVerificationSpecCollection : ICollectionFixture<RequiredVerificationHarness>
{
    /// <summary>The collection name every required-verification spec joins.</summary>
    public const string Name = "RequiredVerification";
}
