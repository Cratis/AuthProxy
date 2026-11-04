// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Represents one callback waiting to be delivered to a service.
/// </summary>
/// <param name="ServiceName">The configured name of the service to call.</param>
/// <param name="Url">The absolute address of the callback endpoint.</param>
/// <param name="Timeout">How long to wait for the service to answer.</param>
/// <param name="Secret">The shared secret to present, or an empty string to present none.</param>
/// <param name="Kind">What is being reported.</param>
/// <param name="Principal">The user the callback is about.</param>
/// <param name="Tenant">The tenant the user is acting in, when one resolved.</param>
/// <param name="Occurred">When the sign-in or return happened.</param>
public sealed record SignInCallbackRequest(
    string ServiceName,
    string Url,
    TimeSpan Timeout,
    string Secret,
    SignInCallbackKind Kind,
    ClientPrincipal Principal,
    string? Tenant,
    DateTimeOffset Occurred);
