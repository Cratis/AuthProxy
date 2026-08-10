// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Runs the trusted-proxy specs against one shared proxy and origin, in sequence.
/// </summary>
/// <remarks>
/// Separate from <see cref="SecuritySpecCollection"/> because it is a different deployment — one that has
/// declared where its ingress is. Serialized because both the origin's recorder and the record of what each
/// request was normalized to hold the most recent request, and two specs running at once would read each
/// other's.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public class TrustedProxySpecCollection : ICollectionFixture<TrustedProxyHarness>
{
    /// <summary>The collection name every trusted-proxy spec joins.</summary>
    public const string Name = "TrustedProxy";
}
