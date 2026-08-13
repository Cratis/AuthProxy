// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A request carrying a protected cookie session and its chunk names.</summary>
/// <param name="Message">The request message.</param>
/// <param name="AuthenticationCookieNames">The primary authentication cookie names presented.</param>
public record SessionRequest(
    HttpRequestMessage Message,
    IReadOnlyList<string> AuthenticationCookieNames);
