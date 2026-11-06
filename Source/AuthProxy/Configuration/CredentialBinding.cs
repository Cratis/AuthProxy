// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Trusted deployment identifiers that bind AuthProxy-issued credentials. Never populate these from caller input.
/// </summary>
public class CredentialBinding
{
    /// <summary>
    /// Gets or sets the resource this deployment serves. Empty means no resource binding is declared.
    /// </summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the deployment environment. Empty means no environment binding is declared.
    /// </summary>
    public string Environment { get; set; } = string.Empty;
}
