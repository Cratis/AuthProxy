// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>The exception that is thrown when a forwarded-identity audience is invalid.</summary>
/// <param name="audience">The audience that could not be used.</param>
public class InvalidForwardedIdentityAudience(string audience)
    : Exception($"'{audience}' is not a forwarded-identity audience. Use 1-128 printable ASCII characters, not blank.");
