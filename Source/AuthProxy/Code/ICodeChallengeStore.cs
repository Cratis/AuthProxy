// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code;

/// <summary>
/// Holds the state of in-flight code sign-ins and request counters.
/// </summary>
public interface ICodeChallengeStore
{
    /// <summary>
    /// Stores a new challenge.
    /// </summary>
    /// <param name="challenge">The challenge to store.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    Task Create(CodeChallenge challenge);

    /// <summary>
    /// Presents a code for a challenge. A wrong code counts an attempt; the challenge is destroyed at the limit. A right
    /// code consumes the challenge exactly once, even when presented concurrently.
    /// </summary>
    /// <param name="scheme">The provider scheme the code is presented to.</param>
    /// <param name="id">The challenge identifier.</param>
    /// <param name="code">The presented code.</param>
    /// <param name="maxAttempts">The number of wrong codes tolerated.</param>
    /// <returns>The outcome.</returns>
    Task<CodeVerification> Verify(string scheme, string id, string code, int maxAttempts);

    /// <summary>
    /// Counts a request against a key and says whether it is still within the limit.
    /// </summary>
    /// <param name="key">What is being limited, such as an address or a client.</param>
    /// <param name="limit">The requests allowed within the window.</param>
    /// <param name="window">The length of the window.</param>
    /// <returns><see langword="true"/> when the request is allowed.</returns>
    Task<bool> TryCount(string key, int limit, TimeSpan window);
}
