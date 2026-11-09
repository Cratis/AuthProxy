// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>Identifies a matched local sign-in or sign-out endpoint.</summary>
/// <param name="IsLogout">Whether the endpoint performs local sign-out.</param>
internal sealed record LocalAuthenticationEndpoint(bool IsLogout);
