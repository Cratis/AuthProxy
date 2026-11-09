// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents how AuthProxy asks a <see cref="BearerIssuer"/> whether an access token it already validated is
/// still active (RFC 7662 token introspection), so a revoked token stops working at the edge.
/// </summary>
/// <remarks>
/// Introspection only ever answers whether the token is active. Nothing the endpoint returns is added to the
/// principal AuthProxy forwards, so it can narrow who gets through, never widen it. A token is only sent to the
/// endpoint after it passed local validation. The client authenticates with HTTP Basic (RFC 6749 §2.3.1), and the
/// secret should be supplied through the environment or a secret store, never committed.
/// </remarks>
public class BearerIssuerIntrospection
{
    /// <summary>
    /// The default for <see cref="MaximumCachedTokens"/>.
    /// </summary>
    public const int DefaultMaximumCachedTokens = 10_000;

    /// <summary>
    /// The default for <see cref="CacheDuration"/>, and the longest a revoked token can keep working.
    /// </summary>
    public static readonly TimeSpan MaximumCacheDuration = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The default for <see cref="Timeout"/>.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// The shortest <see cref="Timeout"/> accepted.
    /// </summary>
    public static readonly TimeSpan MinimumTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// The longest <see cref="Timeout"/> accepted.
    /// </summary>
    public static readonly TimeSpan MaximumTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets or sets the introspection endpoint address.
    /// </summary>
    /// <remarks>An absolute HTTPS URI without query, fragment or user information. Plain HTTP only for a loopback development address.</remarks>
    public string Endpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identifier of the client AuthProxy authenticates to the endpoint as.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client secret. Supply it through the environment or a secret store.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets how long an <em>active</em> answer is reused, at most <see cref="MaximumCacheDuration"/>.
    /// Zero disables the cache. Defaults to <see cref="MaximumCacheDuration"/>.
    /// </summary>
    /// <remarks>This bounds how long a revoked token can still be accepted. An inactive or failed answer is never cached.</remarks>
    public TimeSpan CacheDuration { get; set; } = MaximumCacheDuration;

    /// <summary>
    /// Gets or sets how long AuthProxy waits for the endpoint. Defaults to <see cref="DefaultTimeout"/>.
    /// </summary>
    public TimeSpan Timeout { get; set; } = DefaultTimeout;

    /// <summary>
    /// Gets or sets the most active answers kept. When the cache is full, further answers are not cached.
    /// </summary>
    public int MaximumCachedTokens { get; set; } = DefaultMaximumCachedTokens;

    /// <inheritdoc/>
    public override string ToString() => $"{nameof(BearerIssuerIntrospection)} {{ {nameof(Endpoint)} = {Endpoint}, {nameof(ClientId)} = {ClientId} }}";
}
