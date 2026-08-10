// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Holds what the proxy normalized the most recent request to.
/// </summary>
/// <remarks>
/// A single slot rather than a queue because the specs reading it run one at a time, for the same reason the
/// origin's recorder is read one spec at a time.
/// </remarks>
public sealed class RequestObservations
{
    /// <summary>
    /// Gets or sets the most recently observed request.
    /// </summary>
    public ObservedRequest? Last { get; set; }
}
