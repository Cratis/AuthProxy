// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_the_invitation_callback_sets_cookies;

/// <summary>
/// The callback pipeline with a session cookie domain configured, so session healing also expires host-only copies.
/// </summary>
public class DomainCallbackCookiesAuthProxyFactory : CallbackCookiesAuthProxyFactory
{
    /// <inheritdoc/>
    public override Uri BrowserBase => new("https://app.example.test");

    /// <inheritdoc/>
    protected override string? CookieDomain => ".example.test";
}
