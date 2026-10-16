// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The same deployment as <see cref="SessionCookieHarness"/> with no session cookie domain configured, which is how
/// every deployment that predates the setting runs.
/// </summary>
/// <remarks>
/// It is the regression guard: whatever the shared-cookie specs assert about the cookie being shared, this one
/// asserts the opposite about a deployment that did not ask for it.
/// </remarks>
public class HostOnlySessionCookieHarness : SessionCookieHarness
{
    /// <inheritdoc/>
    protected override string? CookieDomain => null;
}
