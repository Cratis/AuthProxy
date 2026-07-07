// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.ComponentModel.DataAnnotations;

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the client-credentials configuration for a proxied service.
/// </summary>
public class ServiceClientCredentials
{
    /// <summary>
    /// Gets or sets the route prefix that issued bearer tokens are allowed to access.
    /// Defaults to the standard API route prefix.
    /// </summary>
    [Required]
    public string RoutePrefix { get; set; } = "/api";

    /// <summary>
    /// Gets or sets the internal verification endpoint that AuthProxy should call with the supplied client credentials.
    /// Relative values are resolved against the service backend <c>BaseUrl</c>; absolute values are used as-is.
    /// </summary>
    [Required]
    public string VerificationPath { get; set; } = "/.cratis/client-credentials/verify";
}
