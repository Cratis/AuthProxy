// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.ComponentModel.DataAnnotations;

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the URL endpoint of a service (backend or frontend).
/// </summary>
public class ServiceEndpoint
{
    /// <summary>
    /// Gets or sets the base URL of the endpoint (e.g. <c language="text">http://my-service:8080/</c>).
    /// </summary>
    [Required, Url]
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets how long a request proxied to this endpoint may sit idle — with no bytes moving in either
    /// direction — before the proxy cancels it. Leave unset to use <see cref="Service.ActivityTimeout"/>, then
    /// the root <see cref="AuthProxy.ActivityTimeout"/>. Must be greater than zero.
    /// </summary>
    public TimeSpan? ActivityTimeout { get; set; }
}
