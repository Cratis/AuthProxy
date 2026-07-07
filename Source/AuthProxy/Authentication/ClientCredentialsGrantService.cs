// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Orchestrates the back-channel client-credentials token flow.
/// </summary>
/// <param name="serviceResolver">Resolves which configured service should handle the token request.</param>
/// <param name="verifier">Verifies the supplied client credentials against the target service.</param>
/// <param name="tokenProtector">Creates AuthProxy-issued bearer tokens for verified clients.</param>
public class ClientCredentialsGrantService(
    ClientCredentialsServiceResolver serviceResolver,
    ClientCredentialsVerifier verifier,
    ClientCredentialsTokenProtector tokenProtector)
{
    /// <summary>
    /// Processes a client-credentials token request.
    /// </summary>
    /// <param name="grantType">The requested OAuth grant type.</param>
    /// <param name="serviceName">The requested service name.</param>
    /// <param name="clientId">The provided client identifier.</param>
    /// <param name="clientSecret">The provided client secret.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The token issuance result.</returns>
    public async Task<ClientCredentialsGrantResult> GrantAsync(
        string? grantType,
        string? serviceName,
        string? clientId,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(grantType, ClientCredentialsDefaults.GrantType, StringComparison.Ordinal))
        {
            return ClientCredentialsGrantResult.CreateError(
                StatusCodes.Status400BadRequest,
                "unsupported_grant_type",
                "Only the client_credentials grant type is supported.");
        }

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
        {
            return ClientCredentialsGrantResult.CreateError(
                StatusCodes.Status400BadRequest,
                "invalid_request",
                "Both client_id and client_secret are required.");
        }

        if (!serviceResolver.TryResolveForTokenRequest(serviceName, out var service, out var errorDescription))
        {
            return ClientCredentialsGrantResult.CreateError(
                StatusCodes.Status400BadRequest,
                "invalid_request",
                errorDescription);
        }

        var verificationResult = await verifier.VerifyAsync(service, clientId, clientSecret, cancellationToken);
        if (verificationResult.Status == ClientCredentialsVerificationStatus.Rejected)
        {
            return ClientCredentialsGrantResult.CreateError(
                StatusCodes.Status401Unauthorized,
                "invalid_client",
                "The client credentials were rejected by the target service.");
        }

        if (verificationResult.Status == ClientCredentialsVerificationStatus.Failed)
        {
            return ClientCredentialsGrantResult.CreateError(
                StatusCodes.Status502BadGateway,
                "server_error",
                "The target service could not verify the supplied client credentials.");
        }

        return ClientCredentialsGrantResult.Success(
            tokenProtector.CreateToken(service, clientId),
            tokenProtector.ExpiresInSeconds);
    }
}
