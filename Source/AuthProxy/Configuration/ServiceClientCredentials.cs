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
    /// Relative values are resolved against the service backend <c language="text">BaseUrl</c>; absolute HTTP or HTTPS URLs are used as-is.
    /// Leading-slash paths, including the default, resolve at the backend origin while preserving its HTTP or HTTPS scheme.
    /// </summary>
    [Required]
    public string VerificationPath { get; set; } = "/.cratis/client-credentials/verify";

    /// <summary>
    /// Gets or sets how long a chain of refreshed tokens can be used, counted from the original <c language="text">client_credentials</c> grant.
    /// Refreshing a token never extends this deadline, and rotating the client secret at the service does not shorten it.
    /// Use the <see cref="TimeSpan"/> format, for example <c language="text">30.00:00:00</c>. Defaults to 30 days.
    /// </summary>
    public TimeSpan RefreshTokenFamilyLifetime { get; set; } = Cratis.AuthProxy.Authentication.ClientCredentialsDefaults.DefaultRefreshTokenFamilyLifetime;
}
