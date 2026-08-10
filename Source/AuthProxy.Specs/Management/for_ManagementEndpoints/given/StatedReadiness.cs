// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementEndpoints.given;

/// <summary>
/// A readiness check that answers what a spec told it to, and counts being asked.
/// </summary>
/// <param name="ready">What it answers.</param>
/// <remarks>
/// Hand-written rather than substituted. <c>IReadinessCheck</c> is internal, and a dynamic proxy over an
/// internal type would need the proxy generator's assembly named in AuthProxy's own
/// <c>InternalsVisibleTo</c> — a permanent widening of the shipped assembly's surface, to serve a spec.
/// <para>
/// Counting matters as much as answering: liveness must consult nothing, and the only way to see that it
/// did not is to ask this how many times it was called.
/// </para>
/// </remarks>
internal sealed class StatedReadiness(bool ready) : IReadinessCheck
{
    /// <summary>
    /// Gets how many times readiness was asked for.
    /// </summary>
    public int Consulted { get; private set; }

    /// <inheritdoc/>
    public Task<bool> IsReady(CancellationToken cancellationToken)
    {
        Consulted++;

        return Task.FromResult(ready);
    }
}
