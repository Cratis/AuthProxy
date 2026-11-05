// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>A backend's audience, key identifier and secret parameter reference.</summary>
/// <param name="Audience">The backend audience.</param>
/// <param name="KeyId">The signing key identifier.</param>
/// <param name="Secret">The shared secret parameter reference.</param>
/// <remarks>Never resolve or format the secret value for logging.</remarks>
internal sealed record ForwardedIdentityPairing(string Audience, string KeyId, ParameterResource Secret);
