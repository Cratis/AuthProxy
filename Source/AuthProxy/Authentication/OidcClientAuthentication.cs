// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Authenticates AuthProxy's own requests to an OIDC provider with a <c language="text">client_assertion</c> when the provider is
/// configured with a certificate or federated credential.
/// </summary>
static class OidcClientAuthentication
{
    /// <summary>
    /// The <c language="text">client_assertion_type</c> of a JWT client assertion (RFC 7523).
    /// </summary>
    internal const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /// <summary>
    /// Replaces any client secret on a request to the provider with a client assertion.
    /// </summary>
    /// <param name="httpContext">The current <see cref="HttpContext"/>.</param>
    /// <param name="scheme">The provider's authentication scheme.</param>
    /// <param name="provider">The provider registration.</param>
    /// <param name="options">The provider's effective handler options, used to discover its token endpoint.</param>
    /// <param name="message">The request to the provider.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <exception cref="OidcClientCredentialUnavailable">No assertion could be created.</exception>
    internal static async Task Apply(
        HttpContext httpContext,
        string scheme,
        C.OidcProvider provider,
        OpenIdConnectOptions options,
        OpenIdConnectMessage message)
    {
        var audience = await TokenEndpointOf(options, httpContext.RequestAborted);
        var assertions = httpContext.RequestServices.GetRequiredService<IOidcClientAssertions>();
        var assertion = await assertions.Create(scheme, provider, audience, httpContext.RequestAborted);

        message.ClientSecret = null;
        message.ClientAssertionType = JwtBearerAssertionType;
        message.ClientAssertion = assertion;
    }

    /// <summary>
    /// Resolves the provider's token endpoint, which is the audience of every client assertion (OpenID Connect Core
    /// section 9).
    /// </summary>
    /// <param name="options">The provider's effective handler options.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>The token endpoint.</returns>
    /// <exception cref="OidcClientCredentialUnavailable">The provider metadata names no token endpoint.</exception>
    internal static async Task<string> TokenEndpointOf(OpenIdConnectOptions options, CancellationToken cancellationToken)
    {
        var configuration = options.Configuration
            ?? (options.ConfigurationManager is null ? null : await options.ConfigurationManager.GetConfigurationAsync(cancellationToken));

        return string.IsNullOrEmpty(configuration?.TokenEndpoint)
            ? throw new OidcClientCredentialUnavailable($"The OIDC provider at '{options.Authority}' publishes no token endpoint to present a client assertion to.")
            : configuration.TokenEndpoint;
    }
}
