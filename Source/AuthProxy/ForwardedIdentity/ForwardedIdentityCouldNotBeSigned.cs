// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// The exception that is thrown when signed forwarding is configured and a proxied request cannot be signed.
/// </summary>
/// <param name="message">The message describing why the request could not be signed.</param>
/// <remarks>
/// Thrown from the reverse-proxy transform so the request fails with <c language="text">502</c> and is never forwarded
/// unsigned.
/// </remarks>
public class ForwardedIdentityCouldNotBeSigned(string message) : Exception(message);
