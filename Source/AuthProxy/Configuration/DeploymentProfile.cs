// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Selects deployment transport requirements independently of the hosting environment.
/// </summary>
public enum DeploymentProfile
{
    /// <summary>
    /// Signed identity-bearing hops require HTTPS and a client certificate.
    /// </summary>
    Default = 0,

    /// <summary>
    /// Developer machines only: permits HTTP and a missing client certificate on signed hops.
    /// </summary>
    LocalDevelopment = 1
}
