// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The exception that is thrown when a Cratis Identity discovery document does not name the configured authority as its
/// issuer. The issuer the document named is not repeated, since it is untrusted input.
/// </summary>
/// <param name="authority">The configured authority.</param>
public class CratisIdentityIssuerMismatch(string authority)
    : Exception($"The Cratis Identity discovery document does not name the configured authority '{authority}' as its issuer.");
