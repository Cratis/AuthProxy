// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Answers an identity-details denial like a failed sign-in for the OIDC providers that opt in.
/// </summary>
internal static class DeniedSignInResponse
{
    /// <summary>
    /// Determines whether the session of the request belongs to an OIDC provider that answers a denial like a failed sign-in.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <param name="authentication">The current authentication configuration.</param>
    /// <returns><see langword="true"/> when the provider opted in; <see langword="false"/> when it did not or cannot be determined.</returns>
    /// <remarks>
    /// The provider is the one the session records, never one the request names. When it cannot be determined the
    /// answer is <see langword="false"/>, so the existing forbidden response applies.
    /// </remarks>
    internal static bool Applies(HttpContext context, C.Authentication authentication)
    {
        var properties = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult?.Properties;
        if (!SessionProvider.TryRead(context.User, properties, out var scheme))
        {
            return false;
        }

        var providers = authentication.OidcProviders
            .Where(_ => OidcProviderScheme.FromName(_.Name) == scheme)
            .ToArray();

        return providers.Length == 1 && providers[0].DenialResponse == C.OidcDenialResponse.FailedSignIn;
    }

    /// <summary>
    /// Terminates the session and writes the failed-sign-in answer.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <param name="config">The current configuration.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <remarks>
    /// A person navigating is sent to provider selection with the failed-sign-in reason and their destination; every
    /// other caller gets the status an unauthenticated caller already gets. Never the forbidden page, which would say
    /// the identity was recognized but denied.
    /// </remarks>
    internal static async Task Write(HttpContext context, C.AuthProxy config)
    {
        await SessionTermination.SignOutAndClearCookies(context, config.Session, config.Logout);

        if (context.IsDocumentNavigation())
        {
            var returnUrl = RelativeRedirect.Resolve(context.GetPathAndQuery());
            context.Response.Redirect(RemoteAuthenticationFailureHandler.FailedSignInLocation(SignInFailureReason.RemoteFailure, returnUrl));
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }
}
