// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents one additional cookie the logout flow deletes on top of the cookies AuthProxy issues itself.
/// </summary>
/// <remarks>
/// This exists for cookies AuthProxy does not own but that must not survive a logout — typically a cookie
/// written by sibling authentication infrastructure (another proxy on the same or a parent domain) that
/// would otherwise keep the browser half-signed-in. Matching is by exact name only.
/// </remarks>
public class LogoutCookie
{
    /// <summary>
    /// Gets or sets the exact name of the cookie to delete, e.g. <c>_oauth2_proxy_admin</c>.
    /// Entries with an empty name are ignored.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the domain the cookie was scoped to, e.g. <c>.cratis.studio</c>.
    /// When set, the deletion is issued for this domain in addition to the request host — required to kill
    /// a cookie that was written for a parent domain, since a host-scoped deletion cannot touch it.
    /// Leave empty for a cookie scoped to the request host itself.
    /// </summary>
    public string Domain { get; set; } = string.Empty;
}
