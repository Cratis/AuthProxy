// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>The exception that is thrown when a forwarded-identity key identifier is invalid or already taken.</summary>
/// <param name="keyId">The key identifier that could not be used.</param>
public class InvalidForwardedIdentityKeyId(string keyId)
    : Exception($"'{keyId}' is not an available forwarded-identity key identifier. Use a unique identifier matching [A-Za-z0-9_-]{{1,64}} for this backend.");
