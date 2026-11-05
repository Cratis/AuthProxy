// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>The exception that is thrown when pairings request different audiences for one backend.</summary>
/// <param name="backend">The backend resource name.</param>
/// <param name="existing">The already configured audience.</param>
/// <param name="requested">The requested audience.</param>
public class ConflictingForwardedIdentityAudience(string backend, string existing, string requested)
    : Exception($"'{backend}' already verifies audience '{existing}', not '{requested}'. Use the same audience for every pairing of this backend.");
