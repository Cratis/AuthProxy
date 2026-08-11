// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Turns a failed identity-provider round-trip into an answer a person can act on, instead of the
/// unhandled <see cref="Exception"/> the remote authentication handler would otherwise throw — which
/// surfaces in the browser as a blank 500 page.
/// </summary>
/// <remarks>
/// A remote sign-in fails for reasons the person in front of the browser cannot see: a correlation cookie
/// that a previous half-cleared session left stale, an OAuth state that expired in another tab, a consent
/// prompt they declined. Whatever the cause, the recovery is the same — start a fresh sign-in — so every
/// failure clears the transient handshake cookies (removing the very state that poisons retries) and
/// redirects to the provider-selection page with a <see cref="SignInFailureReason"/> the page can show.
/// The failure itself is logged with its scheme and message, so the operator still sees what the browser
/// no longer does.
/// </remarks>
public static class RemoteAuthenticationFailureHandler
{
    /// <summary>
    /// Handles a failed remote authentication round-trip (correlation failure, invalid state, provider
    /// error) by clearing the handshake cookies and redirecting to provider selection.
    /// </summary>
    /// <param name="context">The failure context raised by the remote authentication handler.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static Task HandleRemoteFailure(RemoteFailureContext context)
    {
        GetLogger(context.HttpContext).RemoteSignInFailed(context.Scheme.Name, context.Failure?.Message ?? "(unknown)");
        return Handle(context, context.Properties, SignInFailureReason.RemoteFailure);
    }

    /// <summary>
    /// Handles the identity provider reporting that access was denied — typically the person cancelling
    /// the sign-in or declining consent — by clearing the handshake cookies and redirecting to provider
    /// selection.
    /// </summary>
    /// <param name="context">The access-denied context raised by the remote authentication handler.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static Task HandleAccessDenied(AccessDeniedContext context)
    {
        GetLogger(context.HttpContext).RemoteSignInAccessDenied(context.Scheme.Name);
        return Handle(context, context.Properties, SignInFailureReason.AccessDenied);
    }

    static async Task Handle(
        HandleRequestContext<RemoteAuthenticationOptions> context,
        AuthenticationProperties? properties,
        string reason)
    {
        // The transient correlation/state cookies are what a retry trips over, and the provider callback is
        // the one request where even legacy path-scoped stragglers are visible — clear them all here.
        TransientAuthenticationCookies.Clear(context.HttpContext);

        // A failed link challenge is not a failed sign-in. The person still holds their primary session,
        // and the provider-selection page would answer with full sign-ins — offering to *replace* the very
        // session the link was preserving, and looping straight back into whatever failed. The link flow
        // ends here instead, on its failure page, which also tells an embedding selection page the attempt
        // is over so it can offer a retry.
        if (properties?.Items.TryGetValue(LinkMiddleware.LinkModePropertyKey, out var linkMode) == true
            && linkMode == "true")
        {
            GetLogger(context.HttpContext).LinkChallengeFailed(context.Scheme.Name);
            await LinkFlowPages.WriteFailed(context.HttpContext);
            context.HandleResponse();
            return;
        }

        var location = $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={reason}";

        // Carry the original destination forward when the challenge recorded one, so a successful retry
        // still lands where the person was heading. The value comes from protected authentication state,
        // but it is validated as same-site relative all the same.
        var returnUrl = RelativeRedirect.Resolve(properties?.RedirectUri);
        if (returnUrl != RelativeRedirect.ApplicationRoot)
        {
            location += $"&returnUrl={Uri.EscapeDataString(returnUrl)}";
        }

        context.Response.Redirect(location);
        context.HandleResponse();
    }

    static ILogger GetLogger(HttpContext context) =>
        context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(RemoteAuthenticationFailureHandler).FullName!);
}
