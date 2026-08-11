// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Represents the bounded request AuthProxy sends while verifying a presented capability.
/// </summary>
/// <param name="Capability">The exact value the caller presented, uninterpreted.</param>
/// <param name="Transaction">The opaque identifier AuthProxy authored for this presentation.</param>
/// <param name="Challenge">The independent opaque value AuthProxy authored for this presentation.</param>
public sealed record CapabilityVerificationRequest(string Capability, string Transaction, string Challenge);
