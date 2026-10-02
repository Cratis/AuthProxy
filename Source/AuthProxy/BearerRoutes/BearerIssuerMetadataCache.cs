// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Holds one issuer's synchronized last-good metadata and retrieval deadlines.
/// </summary>
/// <param name="retriever">The issuer's document retriever.</param>
internal sealed class BearerIssuerMetadataCache(IDocumentRetriever retriever) : IDisposable
{
    OpenIdConnectConfiguration? _configuration;

    /// <summary>
    /// Gets the gate serializing retrievals and deadline access.
    /// </summary>
    internal SemaphoreSlim Gate { get; } = new(1, 1);

    /// <summary>
    /// Gets the issuer's document retriever.
    /// </summary>
    internal IDocumentRetriever Retriever { get; } = retriever;

    /// <summary>
    /// Gets or sets the last configuration naming the expected issuer.
    /// </summary>
    internal OpenIdConnectConfiguration? Configuration
    {
        get => Volatile.Read(ref _configuration);
        set => Volatile.Write(ref _configuration, value);
    }

    /// <summary>
    /// Gets or sets the next periodic retrieval deadline.
    /// </summary>
    internal DateTimeOffset AutomaticRefreshAfter { get; set; }

    /// <summary>
    /// Gets or sets the next allowed unknown-key refresh deadline.
    /// </summary>
    internal DateTimeOffset RequestedRefreshAfter { get; set; }

    /// <summary>
    /// Gets or sets the next attempt after a failed retrieval.
    /// </summary>
    internal DateTimeOffset RetryAfter { get; set; }

    /// <summary>
    /// Gets or sets the background retrieval to join before disposing its gate.
    /// </summary>
    internal Task? BackgroundRefresh { get; set; }

    /// <inheritdoc/>
    public void Dispose()
    {
        BackgroundRefresh?.GetAwaiter().GetResult();
        Gate.Dispose();
    }
}
