// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Validates the URLs the contract carries: HTTPS, or HTTP on loopback in development.
/// </summary>
public static class ContractUrl
{
    /// <summary>
    /// Validates a URL value.
    /// </summary>
    /// <param name="value">The URL.</param>
    /// <param name="key">The environment key the URL came from.</param>
    /// <param name="environment">The environment, for the development flag and the message.</param>
    /// <returns>The same URL.</returns>
    /// <exception cref="ApplicationContractException">Thrown when the URL is not acceptable.</exception>
    public static string Validate(string value, string key, ApplicationEnvironment environment)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ApplicationContractException($"Environment '{environment.Name}': key '{key}' must be an absolute URL without user information or fragment.");
        }

        var https = uri.Scheme == Uri.UriSchemeHttps;
        var loopbackHttp = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback && environment.Development;
        if (!https && !loopbackHttp)
        {
            throw new ApplicationContractException(
                $"Environment '{environment.Name}': key '{key}' must use HTTPS. HTTP is accepted only on a loopback address when '{ApplicationContractKeys.DevelopmentKey}' is true.");
        }

        return value;
    }
}
