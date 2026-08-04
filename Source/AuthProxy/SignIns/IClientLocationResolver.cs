// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Defines a system that resolves the approximate origin of a request from its transport metadata.
/// </summary>
public interface IClientLocationResolver
{
    /// <summary>
    /// Resolves the client IP address and a best-effort approximate location for the request.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to resolve from.</param>
    /// <returns>The resolved <see cref="ClientLocation"/>.</returns>
    ClientLocation Resolve(HttpContext context);
}
