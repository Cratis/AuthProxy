// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>The exception that is thrown when an AuthProxy pairs the same backend more than once.</summary>
/// <param name="authProxy">The AuthProxy resource name.</param>
/// <param name="backend">The backend resource name.</param>
public class ForwardedIdentityAlreadyPaired(string authProxy, string backend)
    : Exception($"'{authProxy}' is already paired with '{backend}'. Call WithSignedForwardingTo once per backend.");
