// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>A non-printable exchange outcome. Success is not proof of validity.</summary>
/// <param name="verdict">The outcome.</param>
/// <param name="token">The unvalidated returned token.</param>
/// <param name="expiresIn">The authority's lifetime, in seconds.</param>
/// <param name="retryAfter">A bounded integer delay, if supplied.</param>
public sealed class TokenExchangeResult(TokenExchangeVerdict verdict, string? token = null, int expiresIn = 0, int? retryAfter = null)
{
    /// <summary>Gets the outcome.</summary>
    public TokenExchangeVerdict Verdict { get; } = verdict;

    /// <summary>Gets the returned token; never log this value.</summary>
    public string? Token { get; } = token;

    /// <summary>Gets the lifetime in seconds.</summary>
    public int ExpiresIn { get; } = expiresIn;

    /// <summary>Gets the bounded delay in seconds.</summary>
    public int? RetryAfter { get; } = retryAfter;

    /// <inheritdoc/>
    public override string ToString() => nameof(TokenExchangeResult);
}
