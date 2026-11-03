// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

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
/// Both outcomes end in <c language="text">HandleResponse()</c>. That short-circuit is what stops the remote authentication
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
        var result = await BelongsToThisSession(context, properties)
            ? await context.HttpContext.RequestServices
                .GetRequiredService<ILinkSubjectExchanger>()
                .Exchange(context.Principal, properties, context.Scheme.Name)
            : LinkExchangeResult.Failed;

        if (result == LinkExchangeResult.Success)
        {
            // The return URL comes from protected authentication state, but it is validated as same-site
            // relative all the same — the link callback must never become an open redirect. When no target
            // was recorded (or it did not survive validation) the flow ends on its own completion page
            // rather than booting the whole application into the link window.
            var target = RelativeRedirect.Resolve(properties.RedirectUri);
            context.Response.Redirect(target == RelativeRedirect.ApplicationRoot ? WellKnownPaths.LinkComplete : target);
        }
        else
        {
            GetLogger(context.HttpContext).LinkCallbackFailed(context.Scheme.Name);
            await LinkFlowPages.WriteFailed(context.HttpContext);
        }

        // Short-circuit before the RemoteAuthenticationHandler signs the ticket into the cookie scheme:
        // the linked identity must never replace the primary session — on either outcome.
        context.HandleResponse();
    }

    /// <summary>
    /// Determines whether the callback finishes the link that was started, for the account that started it, with
    /// the provider it was started for.
    /// </summary>
    /// <remarks>
    /// The protected flow state is created only by a confirmed request from a signed-in session, and carries the
    /// provider and the binding of that session's account. A provider that answers with a cross-site form post does
    /// not get the session cookie sent along, so when there is no session on the callback the flow state alone is
    /// relied on, and only when the provider is configured for a form post and the callback is a POST. Whenever a session is present it must be the account that started the link.
    /// </remarks>
    /// <param name="context">The ticket-received context raised by the remote authentication handler.</param>
    /// <param name="properties">The round-tripped challenge properties carrying the flow state.</param>
    /// <returns><see langword="true"/> when the callback may proceed to the exchange; otherwise <see langword="false"/>.</returns>
    static async Task<bool> BelongsToThisSession(TicketReceivedContext context, AuthenticationProperties properties)
    {
        if (!properties.Items.TryGetValue(LinkMiddleware.LinkSchemePropertyKey, out var scheme)
            || !string.Equals(scheme, context.Scheme.Name, StringComparison.Ordinal))
        {
            return false;
        }

        if (!properties.Items.TryGetValue(LinkMiddleware.LinkSessionBindingPropertyKey, out var bound) || string.IsNullOrEmpty(bound))
        {
            return false;
        }

        var session = await context.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (session.Failure is not null)
        {
            return false;
        }

        if (!session.Succeeded)
        {
            // Only a provider configured for a cross-site form post is expected to arrive without the
            // (SameSite=Lax) session cookie; a redirect callback always carries it, so its absence there
            // means the session ended and the link must not complete.
            return IsFormPostCallback(context);
        }

        return LinkSessionBinding.TryCreate(session.Principal, out var current)
            && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(current), Encoding.UTF8.GetBytes(bound));
    }

    static bool IsFormPostCallback(TicketReceivedContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            return false;
        }

        var authentication = context.HttpContext.RequestServices
            .GetRequiredService<IOptionsMonitor<C.AuthProxy>>()
            .CurrentValue.Authentication;

        return authentication.OidcProviders.Any(_ =>
            _.ResponseMode == C.OidcResponseMode.FormPost
            && string.Equals(OidcProviderScheme.FromName(_.Name), context.Scheme.Name, StringComparison.Ordinal));
    }

    static ILogger GetLogger(HttpContext context) =>
        context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(LinkCallbackCompletion).FullName!);
}
