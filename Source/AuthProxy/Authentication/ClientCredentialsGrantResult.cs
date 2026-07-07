// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Represents the outcome of a client-credentials token request.
/// </summary>
public record ClientCredentialsGrantResult
{
    ClientCredentialsGrantResult()
    {
    }

    /// <summary>
    /// Gets the HTTP status code to return.
    /// </summary>
    public required int StatusCode { get; init; }

    /// <summary>
    /// Gets the issued access token, when the request succeeded.
    /// </summary>
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>
    /// Gets the token type to return.
    /// </summary>
    public string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// Gets the token lifetime in seconds.
    /// </summary>
    public int ExpiresIn { get; init; }

    /// <summary>
    /// Gets the OAuth error code, when the request failed.
    /// </summary>
    public string Error { get; init; } = string.Empty;

    /// <summary>
    /// Gets the OAuth error description, when the request failed.
    /// </summary>
    public string ErrorDescription { get; init; } = string.Empty;

    /// <summary>
    /// Gets whether the request succeeded.
    /// </summary>
    public bool Succeeded => StatusCode is >= 200 and < 300;

    /// <summary>
    /// Creates a successful token result.
    /// </summary>
    /// <param name="accessToken">The issued access token.</param>
    /// <param name="expiresIn">The token lifetime in seconds.</param>
    /// <returns>A successful token result.</returns>
    public static ClientCredentialsGrantResult Success(string accessToken, int expiresIn) => new()
    {
        StatusCode = StatusCodes.Status200OK,
        AccessToken = accessToken,
        ExpiresIn = expiresIn,
    };

    /// <summary>
    /// Creates an OAuth error result.
    /// </summary>
    /// <param name="statusCode">The HTTP status code to return.</param>
    /// <param name="error">The OAuth error code.</param>
    /// <param name="errorDescription">The OAuth error description.</param>
    /// <returns>An error result.</returns>
    public static ClientCredentialsGrantResult CreateError(int statusCode, string error, string errorDescription) => new()
    {
        StatusCode = statusCode,
        Error = error,
        ErrorDescription = errorDescription,
    };
}
