// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code;

/// <summary>
/// The result of presenting a code.
/// </summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Challenge">The consumed challenge, when <paramref name="Outcome"/> is <see cref="CodeVerificationOutcome.Verified"/>.</param>
public sealed record CodeVerification(CodeVerificationOutcome Outcome, CodeChallenge? Challenge = null);
