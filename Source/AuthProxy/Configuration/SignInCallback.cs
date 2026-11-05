// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the optional sign-in callback of one service: a server-to-server notification to the application
/// that a user signed in, or came back with a session that was already established.
/// </summary>
/// <remarks>
/// Off by default — a service without this section is never called. It lets a managed product learn who is
/// active ("last seen") and run first-request work without every application implementing the detection itself.
/// It is not the same as <see cref="SignIn.NotifyUrl"/>, which is one proxy-wide endpoint that reports a sign-in
/// together with the client's location and browser; this one is declared per service and also reports returns.
/// </remarks>
public class SignInCallback
{
    /// <summary>
    /// The default time that has to pass before the same user is reported as having returned to the same service again.
    /// </summary>
    public static readonly TimeSpan DefaultInterval = TimeSpan.FromHours(12);

    /// <summary>
    /// The default time AuthProxy waits for the service to answer a callback.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets the absolute path on the service's <see cref="Service.Backend"/> that receives the callback, for
    /// example <c language="text">/.cratis/showrunner/sign-in</c>. Required when the section is present.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the least time between two <c language="text">Returned</c> callbacks for the same user and service.
    /// Defaults to <see cref="DefaultInterval"/>.
    /// </summary>
    public TimeSpan Interval { get; set; } = DefaultInterval;

    /// <summary>
    /// Gets or sets how long AuthProxy waits for the service to answer a callback before it gives up.
    /// Defaults to <see cref="DefaultTimeout"/>. The wait is on a background channel, never on the user's request.
    /// </summary>
    public TimeSpan Timeout { get; set; } = DefaultTimeout;

    /// <summary>
    /// Gets or sets a shared secret sent to the service in the <c language="text">x-cratis-sign-in-callback-secret</c> header,
    /// so the service can tell a callback from AuthProxy from any other caller on its network. Leave empty to send none.
    /// </summary>
    /// <remarks>
    /// Supply it from a secret store or the environment, never from a committed file. AuthProxy never logs it.
    /// </remarks>
    public string Secret { get; set; } = string.Empty;
}
