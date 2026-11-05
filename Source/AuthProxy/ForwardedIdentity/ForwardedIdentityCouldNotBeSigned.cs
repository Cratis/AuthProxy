// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Prevents an opted-in identity-bearing request from leaving without a proof.</summary>
internal sealed class ForwardedIdentityCouldNotBeSigned : HttpRequestException
{
    /// <summary>Initializes a new instance of the <see cref="ForwardedIdentityCouldNotBeSigned"/> class.</summary>
    internal ForwardedIdentityCouldNotBeSigned() : base("Forwarded identity signing refused (Refused).")
    {
    }
}
