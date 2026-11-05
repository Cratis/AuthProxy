// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A final wire request captured by the independent v1 origin.</summary>
/// <param name="Method">The observed method.</param>
/// <param name="RawTarget">The exact escaped origin-form target.</param>
/// <param name="Headers">The exact values of every observed header.</param>
/// <param name="Verified">Whether the independent verifier accepted the proof.</param>
public sealed record ForwardedIdentityObservation(string Method, string RawTarget, IReadOnlyDictionary<string, string[]> Headers, bool Verified)
{
    /// <summary>Gets the singular proof, or an empty string when absent.</summary>
    public string Proof => Headers.TryGetValue("x-cratis-forwarded-identity-signature", out var values) ? values.Single() : string.Empty;
}
