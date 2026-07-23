// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Defines a system that posts the subject of a freshly authenticated link identity to the application's
/// configured link-exchange endpoint, so the application can associate it with the signed-in user.
/// </summary>
public interface ILinkSubjectExchanger
{
    /// <summary>
    /// Posts the authenticated subject and identity provider for a link to the application, authenticated
    /// with the one-time link token carried in <paramref name="properties"/>.
    /// </summary>
    /// <param name="principal">The principal produced by the second provider authentication.</param>
    /// <param name="properties">The round-tripped challenge properties holding the link token.</param>
    /// <returns>The <see cref="LinkExchangeResult"/> describing the outcome.</returns>
    Task<LinkExchangeResult> Exchange(ClaimsPrincipal? principal, AuthenticationProperties properties);
}
