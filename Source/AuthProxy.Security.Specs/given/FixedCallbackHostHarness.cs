// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The same three hosts as <see cref="SessionCookieHarness"/> with one host, <see cref="CallbackHostName"/>, fixed as
/// the place the identity-provider handshake runs.
/// </summary>
public class FixedCallbackHostHarness : SessionCookieHarness
{
    /// <summary>The host the handshake runs on.</summary>
    public const string CallbackHostName = "auth.example.test";

    /// <inheritdoc/>
    protected override string? CallbackHost => CallbackHostName;
}
