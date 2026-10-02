// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The exception that is thrown when the client credential configured for an OIDC provider cannot be loaded or
/// cannot produce a client assertion.
/// </summary>
/// <param name="message">The message describing why the credential is unavailable.</param>
/// <param name="innerException">The underlying failure, when there is one.</param>
public class OidcClientCredentialUnavailable(string message, Exception? innerException = null) : Exception(message, innerException);
