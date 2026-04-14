// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Configuration;

namespace Cratis.Ingress;

/// <summary>
/// Represents the details of a single OIDC provider as returned by the providers endpoint.
/// </summary>
/// <param name="Name">Display name of the provider shown on the login page.</param>
/// <param name="Type">Provider type / brand (used to pick the correct logo).</param>
/// <param name="LoginUrl">The ingress-relative URL that initiates the login flow for this provider.</param>
public record OidcProviderInfo(string Name, OidcProviderType Type, string LoginUrl);
