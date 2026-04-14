// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.ComponentModel.DataAnnotations;

namespace Cratis.Ingress.Configuration;

/// <summary>
/// Represents the URL endpoint of a microservice part (backend or frontend).
/// </summary>
public class MicroserviceEndpointConfig
{
    /// <summary>
    /// Gets or sets the base URL of the endpoint (e.g. <c>http://my-service:8080/</c>).
    /// </summary>
    [Required, Url]
    public string BaseUrl { get; set; } = string.Empty;
}
