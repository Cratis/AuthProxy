// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Answers the provider callback of the session-preserving credential-link flow with what actually
/// happened, rather than reporting completion for an exchange the application never recorded.
/// </summary>
/// <remarks>
/// <see cref="ILinkSubjectExchanger"/> reports a bounded failure for six distinct causes, and in five of
/// them the application is never contacted at all — it holds no record of the attempt and cannot discover
/// the failure by any other means. Redirecting to the challenge's return URL regardless of the outcome
/// therefore tells the browser, the person in front of it, and the application that a credential was linked
/// when none was. Only a successful exchange earns the completion redirect; every failure is answered with a
/// generic failure page instead.
/// <para>
/// That page is deliberately the same for every cause. "The provider identity is unknown", "the account does
/// not exist" and "the endpoint was unreachable" are answers worth enumerating, so the browser is told only
/// that the link did not complete, while the cause is logged where the operator can see it.
/// </para>
/// <para>
/// Both outcomes end in <c>HandleResponse()</c>. That short-circuit is what stops the remote authentication
/// handler signing the second identity into the primary cookie scheme — without it a failed link quietly
/// swaps the account the person is signed in as.
/// </para>
/// </remarks>
public static class LinkCallbackCompletion
{
    /// <summary>
    /// Exchanges the freshly authenticated subject with the application and answers the browser according
    /// to the outcome, without ever signing the linked identity into the primary session.
    /// </summary>
    /// <param name="context">The ticket-received context raised by the remote authentication handler.</param>
    /// <param name="properties">The round-tripped challenge properties carrying the link token and return URL.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static async Task Complete(TicketReceivedContext context, AuthenticationProperties properties)
    {
        var exchanger = context.HttpContext.RequestServices.GetRequiredService<ILinkSubjectExchanger>();
        var result = await exchanger.Exchange(context.Principal, properties);

        if (result == LinkExchangeResult.Success)
        {
            // The return URL comes from protected authentication state, but it is validated as same-site
            // relative all the same — the link callback must never become an open redirect.
            context.Response.Redirect(RelativeRedirect.Resolve(properties.RedirectUri));
        }
        else
        {
            GetLogger(context.HttpContext).LinkCallbackFailed(context.Scheme.Name);
            await context.HttpContext.RequestServices
                .GetRequiredService<IErrorPageProvider>()
                .WriteErrorPageAsync(context.HttpContext, WellKnownPageNames.LinkFailed, StatusCodes.Status403Forbidden);
        }

        // Short-circuit before the RemoteAuthenticationHandler signs the ticket into the cookie scheme:
        // the linked identity must never replace the primary session — on either outcome.
        context.HandleResponse();
    }

    static ILogger GetLogger(HttpContext context) =>
        context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(LinkCallbackCompletion).FullName!);
}
