// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The downstream verification outcome.
/// </summary>
/// <param name="Status">The high-level verification status.</param>
/// <param name="StatusCode">The downstream HTTP status code.</param>
/// <param name="Tenant">The tenant the verified client belongs to, when the target service resolved one.</param>
public record ClientCredentialsVerificationResult(
    ClientCredentialsVerificationStatus Status,
    HttpStatusCode StatusCode,
    string? Tenant = null);
