// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code;

/// <summary>
/// The outcome of presenting a code.
/// </summary>
public enum CodeVerificationOutcome
{
    /// <summary>The code was right; the challenge is consumed and cannot be used again.</summary>
    Verified = 0,

    /// <summary>The code was wrong and the challenge can still be tried.</summary>
    Wrong = 1,

    /// <summary>The challenge is unknown, expired, used, exhausted, or has no eligible subject.</summary>
    Refused = 2
}
