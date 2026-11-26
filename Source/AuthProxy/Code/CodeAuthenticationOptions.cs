// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Code;

/// <summary>
/// The options of one code sign-in scheme.
/// </summary>
public class CodeAuthenticationOptions : RemoteAuthenticationOptions
{
    /// <summary>
    /// Gets or sets the configured provider this scheme serves.
    /// </summary>
    public C.OidcProvider Provider { get; set; } = new();

    /// <summary>
    /// Gets or sets the issuer the sign-in is attributed to.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the protected format of the sign-in state carried through the pages.
    /// </summary>
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;
}
