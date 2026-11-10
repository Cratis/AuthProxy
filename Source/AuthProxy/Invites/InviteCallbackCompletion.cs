// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Completes a pending invitation on the provider callback itself, so no follow-up request stands between
/// the sign-in and the completed invitation.
/// </summary>
/// <remarks>
/// The post-login exchange in <see cref="InviteMiddleware"/> depends on the browser presenting the fresh
/// session cookie on the request after the callback's redirect — and browsers have been observed to send
/// that follow-up request without it. The middleware then sees an unauthenticated request and serves the
/// invitation's provider selection a second time, which is how every invitation acceptance grew a second,
/// confusing selection page. Completing on the callback removes the dependency: the exchange runs while the
/// freshly authenticated ticket is in hand, before any redirect is answered.
/// <para>
/// A callback is an invitation's own only when the round-tripped challenge properties carry the capability
/// binding for the exact pending invitation — the binding placed there when the challenge was started
/// (<see cref="InvitationAuthenticationState"/>). A callback without it — a deployment where the binding
/// does not survive the provider round-trip, a sign-in unrelated to the pending invitation — is left
/// entirely alone, and the middleware's Phase 2 answers the follow-up request exactly as it always has.
/// </para>
/// <para>
/// Unlike the credential-link flow (<see cref="Links.LinkCallbackCompletion"/>), an invitation sign-in is a
/// genuine sign-in: the remote handler's cookie sign-in is never suppressed on the completion paths. Where a
/// terminal failure page must be written instead of the handler's redirect, the session is signed in here
/// first — the middleware writes those same pages to an already-authenticated request, and the person did
/// authenticate successfully; it is the invitation completion that failed.
/// </para>
/// <para>
/// Where the middleware signals the lobby redirect through
/// <see cref="InviteMiddleware.LobbyRedirectUrlItemKey"/> for <see cref="InviteRedirectMiddleware"/> to
/// answer, the callback owns its response directly: the handler redirects wherever
/// <see cref="TicketReceivedContext.ReturnUri"/> points after sign-in, so the lobby target is placed there
/// and no item key is involved.
/// </para>
/// </remarks>
static class InviteCallbackCompletion
{
    /// <summary>
    /// Completes the pending invitation this callback answers, when it answers one.
    /// </summary>
    /// <param name="context">The ticket-received context raised by the remote authentication handler.</param>
    /// <returns>What was decided, and therefore what remains for the handler to do.</returns>
    public static async Task<InviteCallbackCompletionResult> TryComplete(TicketReceivedContext context)
    {
        var httpContext = context.HttpContext;
        var properties = context.Properties;
        if (!TryGetOwnInvitation(context, properties, out var inviteToken))
        {
            // Not this invitation's own challenge coming back - including the known deployments where the
            // capability binding does not survive the provider round-trip. Nothing is exchanged here; the
            // post-login middleware remains the answer for those, exactly as before.
            return InviteCallbackCompletionResult.NotCompleted;
        }

        var services = httpContext.RequestServices;
        var logger = GetLogger(httpContext);

        if (!await StillValidates(context, logger, inviteToken))
        {
            return InviteCallbackCompletionResult.NotCompleted;
        }

        var completion = services.GetRequiredService<IInviteCompletion>();
        var exchangeResult = await completion.ExchangeForTicket(httpContext, inviteToken, context.Principal!, properties!);
        return await AnswerExchange(context, completion, inviteToken, exchangeResult);
    }

    static async Task<InviteCallbackCompletionResult> AnswerExchange(
        TicketReceivedContext context,
        IInviteCompletion completion,
        string inviteToken,
        InviteExchangeResult exchangeResult)
    {
        var logger = GetLogger(context.HttpContext);
        return exchangeResult switch
        {
            InviteExchangeResult.Success => CompleteSuccessfully(context, completion, inviteToken, logger),
            InviteExchangeResult.DuplicateSubject => await AnswerDuplicateSubject(context, logger),
            InviteExchangeResult.EmailMismatch => await AnswerWithPage(context, logger, exchangeResult, new(WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden)),
            InviteExchangeResult.EmailUnavailable => await AnswerWithPage(context, logger, exchangeResult, new(WellKnownPageNames.InvitationEmailUnavailable, StatusCodes.Status403Forbidden)),
            _ => await AnswerFailure(context, logger),
        };
    }

    // Re-validate the capability exactly as the post-login exchange does before forwarding it. A
    // capability that no longer validates is not answered here: the middleware already owns the
    // expired/invalid answers, and the follow-up request reaches them unchanged.
    static async Task<bool> StillValidates(TicketReceivedContext context, ILogger logger, string inviteToken)
    {
        var httpContext = context.HttpContext;
        var tokenValidator = httpContext.RequestServices.GetRequiredService<IInviteTokenValidator>();
        var validationResult = await tokenValidator.ValidateDetailed(inviteToken, httpContext.RequestAborted);
        if (validationResult == InviteTokenValidationResult.Valid)
        {
            return true;
        }

        logger.InvitationCallbackTokenNoLongerValidates(context.Scheme.Name, validationResult);
        return false;
    }

    static bool TryGetOwnInvitation(TicketReceivedContext context, AuthenticationProperties? properties, out string inviteToken)
    {
        inviteToken = string.Empty;
        if (properties is null || context.Principal is null)
        {
            return false;
        }

        return context.HttpContext.TryGetPendingInvitationToken(out inviteToken)
            && InvitationAuthenticationState.WasEstablishedFor(properties, inviteToken);
    }

    static InviteCallbackCompletionResult CompleteSuccessfully(
        TicketReceivedContext context,
        IInviteCompletion completion,
        string inviteToken,
        ILogger logger)
    {
        var httpContext = context.HttpContext;
        PendingInvitationCookies.Delete(httpContext);

        // The completion travels in the session about to be signed in, so any follow-up request that
        // replays a stale pending-invitation cookie - or navigates back to the invitation URL - is
        // recognized as already answered instead of being offered provider selection or a second exchange.
        InvitationAuthenticationState.MarkCompleted(context.Properties!, inviteToken);
        logger.InvitationCompletedOnCallback(context.Scheme.Name);

        if (completion.TryResolveLobbyRedirect(httpContext, inviteToken, out var lobbyRedirectUrl))
        {
            context.ReturnUri = lobbyRedirectUrl;
            return InviteCallbackCompletionResult.CompletedWithRedirect;
        }

        // ReturnUrl, or an unavailable Lobby destination, keeps the challenge's own return URL and lets the
        // handler's normal post-sign-in redirect resolution apply.
        return InviteCallbackCompletionResult.CompletedTowardReturnUrl;
    }

    static async Task<InviteCallbackCompletionResult> AnswerDuplicateSubject(TicketReceivedContext context, ILogger logger)
    {
        logger.InvitationCallbackExchangeDidNotSucceed(context.Scheme.Name, InviteExchangeResult.DuplicateSubject);
        PendingInvitationCookies.Delete(context.HttpContext);

        var config = context.HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue;
        var subjectAlreadyExistsUrl = config.Invite?.SubjectAlreadyExistsUrl;
        if (!string.IsNullOrWhiteSpace(subjectAlreadyExistsUrl))
        {
            context.ReturnUri = subjectAlreadyExistsUrl;
            return InviteCallbackCompletionResult.CompletedWithRedirect;
        }

        return await WritePage(context, new(WellKnownPageNames.InvitationSubjectAlreadyExists, StatusCodes.Status409Conflict));
    }

    static async Task<InviteCallbackCompletionResult> AnswerWithPage(
        TicketReceivedContext context,
        ILogger logger,
        InviteExchangeResult exchangeResult,
        ErrorPage page)
    {
        logger.InvitationCallbackExchangeDidNotSucceed(context.Scheme.Name, exchangeResult);
        PendingInvitationCookies.Delete(context.HttpContext);
        return await WritePage(context, page);
    }

    static async Task<InviteCallbackCompletionResult> AnswerFailure(TicketReceivedContext context, ILogger logger)
    {
        var config = context.HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue;
        if (config.Invite?.Attestation is not null)
        {
            return await AnswerWithPage(context, logger, InviteExchangeResult.Failed, new(WellKnownPageNames.InvitationInvalid, StatusCodes.Status403Forbidden));
        }

        // A legacy-protocol failure writes no page in the middleware - the request simply continues down
        // the pipeline. That continuation cannot be reproduced from inside the authentication handler, so
        // the pending invitation is deliberately left in place and the sign-in completes normally: the
        // follow-up request runs the middleware's own exchange and produces exactly today's outcome.
        logger.InvitationCallbackExchangeDidNotSucceed(context.Scheme.Name, InviteExchangeResult.Failed);
        return InviteCallbackCompletionResult.NotCompleted;
    }

    static async Task<InviteCallbackCompletionResult> WritePage(TicketReceivedContext context, ErrorPage page)
    {
        // The page replaces the handler's own sign-in-and-redirect, but the sign-in itself still happened -
        // the middleware writes this same page to an already-authenticated request, and the person did
        // authenticate; it is the invitation completion that failed. Sign the ticket in exactly as the
        // handler would have before answering.
        await context.HttpContext.SignInAsync(context.Options.SignInScheme, context.Principal!, context.Properties);

        var errorPageProvider = context.HttpContext.RequestServices.GetRequiredService<IErrorPageProvider>();
        var isEmailMismatch = string.Equals(page.Name, WellKnownPageNames.InvitationEmailMismatch, StringComparison.Ordinal);
        var substitutions = isEmailMismatch || string.Equals(page.Name, WellKnownPageNames.InvitationEmailUnavailable, StringComparison.Ordinal)
            ? InvitationPageEmails.ForRequest(context.HttpContext, includeAssertedEmail: isEmailMismatch)
            : null;
        await errorPageProvider.WriteErrorPageAsync(context.HttpContext, page.Name, page.StatusCode, substitutions);
        context.HandleResponse();
        return InviteCallbackCompletionResult.ResponseHandled;
    }

    static ILogger GetLogger(HttpContext context) =>
        context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(InviteCallbackCompletion).FullName!);

    readonly record struct ErrorPage(string Name, int StatusCode);
}
