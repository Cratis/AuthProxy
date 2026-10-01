// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Represents the service a request is routed to.
/// </summary>
/// <param name="Name">The configured service key.</param>
/// <param name="Service">The service configuration.</param>
public sealed record RoutedService(string Name, C.Service Service);
