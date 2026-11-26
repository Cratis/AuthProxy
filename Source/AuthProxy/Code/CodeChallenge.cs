// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code;

/// <summary>
/// The persisted state of one issued code. The code itself is never stored, only a salted hash.
/// </summary>
/// <param name="Id">The opaque challenge identifier.</param>
/// <param name="Scheme">The provider scheme the challenge belongs to.</param>
/// <param name="Address">The normalized e-mail address the code was requested for.</param>
/// <param name="Subject">The stable subject the application named, or empty when the address is not eligible.</param>
/// <param name="Salt">The random salt of the hash.</param>
/// <param name="Hash">The salted hash of the code.</param>
/// <param name="ExpiresAt">When the code stops being usable.</param>
/// <param name="Attempts">The number of wrong codes presented so far.</param>
/// <param name="Consumed">Whether the challenge has been used.</param>
public sealed record CodeChallenge(
    string Id,
    string Scheme,
    string Address,
    string Subject,
    string Salt,
    string Hash,
    DateTimeOffset ExpiresAt,
    int Attempts,
    bool Consumed);
