// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Why a value cannot be used as the domain of a shared cookie.
/// </summary>
public enum CookieDomainRejection
{
    /// <summary>
    /// The value is usable.
    /// </summary>
    None = 0,

    /// <summary>
    /// The value is not a host name.
    /// </summary>
    NotAHost = 1,

    /// <summary>
    /// The value names a port, which a cookie domain cannot carry.
    /// </summary>
    HasPort = 2,

    /// <summary>
    /// The value is an IP address, which cannot be shared with sibling hosts.
    /// </summary>
    IpAddress = 3,

    /// <summary>
    /// The value has no dot, so it is a bare top-level domain or a single-label host.
    /// </summary>
    SingleLabel = 4,

    /// <summary>
    /// The value is not ASCII. A domain attribute must be written in its punycode form.
    /// </summary>
    NotAscii = 5
}
