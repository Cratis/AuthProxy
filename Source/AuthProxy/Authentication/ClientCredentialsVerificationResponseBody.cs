// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The optional JSON body a downstream verification endpoint can return alongside a successful response.
/// </summary>
/// <param name="Tenant">The tenant the verified client belongs to, when the target service resolves one.</param>
public record ClientCredentialsVerificationResponseBody(string? Tenant = null);
