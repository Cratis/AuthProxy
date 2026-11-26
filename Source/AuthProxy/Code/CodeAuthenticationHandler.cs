// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Code;

/// <summary>
/// Signs a person in with a one-time code that AuthProxy issues and verifies, and the application delivers.
/// </summary>
/// <remarks>
/// The whole flow runs on the scheme's callback path. A challenge redirects there with the protected sign-in state; the
/// path shows the address page, then the code page, and ends in a successful ticket that follows the same pipeline as
/// any other provider. An address the application does not accept looks exactly like one it does.
/// </remarks>
/// <param name="options">The scheme options.</param>
/// <param name="loggerFactory">Creates the loggers.</param>
/// <param name="encoder">The URL encoder.</param>
/// <param name="store">Holds challenges and request counters.</param>
/// <param name="delivery">Asks the application to deliver a code.</param>
/// <param name="pages">Writes the sign-in pages.</param>
/// <param name="locations">Resolves the client address behind trusted proxies.</param>
/// <param name="invites">Reads the claims of an invitation capability.</param>
/// <param name="proxyConfig">The AuthProxy configuration.</param>
/// <param name="timeProvider">The clock.</param>
public sealed class CodeAuthenticationHandler(
    IOptionsMonitor<CodeAuthenticationOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    ICodeChallengeStore store,
    ICodeDelivery delivery,
    IErrorPageProvider pages,
    IClientLocationResolver locations,
    IInviteTokenValidator invites,
    IOptionsMonitor<C.AuthProxy> proxyConfig,
    TimeProvider timeProvider)
    : RemoteAuthenticationHandler<CodeAuthenticationOptions>(options, loggerFactory, encoder)
{
    const string StateField = "state";
    const string StepField = "step";
    const string EmailField = "email";
    const string ChallengeField = "challenge";
    const string CodeField = "code";
    const string RequestStep = "request";
    const string VerifyStep = "verify";
    const string XsrfKey = ".xsrf";

    readonly ILogger _logger = loggerFactory.CreateLogger<CodeAuthenticationHandler>();

    C.CodeSignIn Settings => Options.Provider.Code ?? new();

    /// <inheritdoc/>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        properties.RedirectUri ??= $"{Request.PathBase}{Request.Path}{Request.QueryString}";
        GenerateCorrelationId(properties);
        var state = Options.StateDataFormat.Protect(properties);
        Response.Redirect($"{Request.PathBase}{Options.CallbackPath}?{StateField}={Uri.EscapeDataString(state)}");
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var protectedState = Request.HasFormContentType
            ? Request.Form[StateField].ToString()
            : Request.Query[StateField].ToString();
        var properties = string.IsNullOrEmpty(protectedState) ? null : Options.StateDataFormat.Unprotect(protectedState);
        if (properties is null || !HasCorrelation(properties))
        {
            return HandleRequestResult.Fail("The sign-in state is missing or does not belong to this browser.");
        }

        if (!HttpMethods.IsPost(Request.Method) || !Request.HasFormContentType)
        {
            await WriteEmailPage(properties, protectedState, string.Empty);
            return HandleRequestResult.Handle();
        }

        var form = await Request.ReadFormAsync();
        return form[StepField].ToString() switch
        {
            RequestStep => await RequestCode(properties, protectedState, form),
            VerifyStep => await VerifyCode(properties, protectedState, form),
            _ => HandleRequestResult.Fail("Unknown code sign-in step."),
        };
    }

    static string Normalize(string address) => address.Trim().ToLowerInvariant();

    static string NewChallengeId() => Attestations.AttestationSigner.CreateOpaqueValue();

    bool HasCorrelation(AuthenticationProperties properties) =>
        properties.Items.TryGetValue(XsrfKey, out var correlation)
        && !string.IsNullOrEmpty(correlation)
        && Request.Cookies.TryGetValue(Options.CorrelationCookie.Name + correlation, out var cookie)
        && !string.IsNullOrEmpty(cookie);

    bool TryGetBoundInvitation(AuthenticationProperties properties, out string address, out string invitationId)
    {
        address = string.Empty;
        invitationId = string.Empty;
        var token = Request.Cookies[Cookies.InviteToken];
        var emailClaim = proxyConfig.CurrentValue.Invite?.EmailClaim;
        if (string.IsNullOrEmpty(token)
            || string.IsNullOrWhiteSpace(emailClaim)
            || !InvitationAuthenticationState.WasEstablishedFor(properties, token)
            || !invites.TryGetClaim(token, emailClaim, out var invited)
            || !InviteMiddleware.IsAnEmailAddress(invited))
        {
            return false;
        }

        address = Normalize(invited);
        invites.TryGetClaim(token, "jti", out invitationId);
        return true;
    }

    string Action() => $"{Request.PathBase}{Options.CallbackPath}";

    Task WriteEmailPage(AuthenticationProperties properties, string state, string error) =>
        CodePages.WriteEmail(
            Context,
            pages,
            Action(),
            state,
            Options.Provider.Name,
            TryGetBoundInvitation(properties, out var bound, out _) ? bound : string.Empty,
            TryGetBoundInvitation(properties, out _, out _),
            error);

    async Task<HandleRequestResult> RequestCode(AuthenticationProperties properties, string state, IFormCollection form)
    {
        var bound = TryGetBoundInvitation(properties, out var invitedAddress, out var invitationId);
        var address = bound ? invitedAddress : Normalize(form[EmailField].ToString());
        if (!InviteMiddleware.IsAnEmailAddress(address))
        {
            await WriteEmailPage(properties, state, "invalid-email");
            return HandleRequestResult.Handle();
        }

        var settings = Settings;
        var subject = string.Empty;
        var now = timeProvider.GetUtcNow();
        var code = CodeHash.NewCode(settings.CodeLength);
        var expiresAt = now + settings.Lifetime;

        if (await IsWithinLimits(settings, address))
        {
            var locale = Request.Headers.AcceptLanguage.ToString().Split(',', ';')[0].Trim();
            var delivered = await delivery.Deliver(
                settings,
                new CodeRequest(
                    address,
                    code,
                    bound ? "invitation" : "signIn",
                    bound ? invitationId : null,
                    string.IsNullOrEmpty(locale) ? "en" : locale,
                    expiresAt));
            subject = delivered ?? string.Empty;
        }

        var salt = CodeHash.NewSalt();
        var challenge = new CodeChallenge(
            NewChallengeId(),
            Scheme.Name,
            address,
            subject,
            salt,
            CodeHash.Compute(salt, code),
            expiresAt,
            0,
            false);
        await store.Create(challenge);

        await CodePages.WriteVerify(Context, pages, Action(), state, Options.Provider.Name, address, challenge.Id, settings.CodeLength, string.Empty);
        return HandleRequestResult.Handle();
    }

    async Task<HandleRequestResult> VerifyCode(AuthenticationProperties properties, string state, IFormCollection form)
    {
        var settings = Settings;
        var challengeId = form[ChallengeField].ToString();
        var presented = form[CodeField].ToString().Trim();
        var address = form["address"].ToString();

        if (presented.Length != settings.CodeLength || !presented.All(char.IsAsciiDigit))
        {
            await WriteVerifyAgain(state, challengeId, address, "wrong");
            return HandleRequestResult.Handle();
        }

        var result = await store.Verify(Scheme.Name, challengeId, presented, settings.MaxAttempts);
        switch (result.Outcome)
        {
            case CodeVerificationOutcome.Verified:
                return Succeed(properties, result.Challenge!);

            case CodeVerificationOutcome.Wrong:
                await WriteVerifyAgain(state, challengeId, address, "wrong");
                return HandleRequestResult.Handle();

            default:
                _logger.CodeSignInRefused("expired, used, exhausted or unknown challenge");
                await WriteEmailPage(properties, state, "start-over");
                return HandleRequestResult.Handle();
        }
    }

    Task WriteVerifyAgain(string state, string challengeId, string address, string error) =>
        CodePages.WriteVerify(Context, pages, Action(), state, Options.Provider.Name, address, challengeId, Settings.CodeLength, error);

    HandleRequestResult Succeed(AuthenticationProperties properties, CodeChallenge challenge)
    {
        if (!ValidateCorrelationId(properties))
        {
            return HandleRequestResult.Fail("Correlation failed.");
        }

        var identity = new ClaimsIdentity(Scheme.Name, "name", "role");
        identity.AddClaim(new Claim("sub", challenge.Subject));
        identity.AddClaim(new Claim("email", challenge.Address));
        identity.AddClaim(new Claim("email_verified", bool.TrueString.ToLowerInvariant()));

        properties.Items[Authentication.FreshAuthenticationChallenge.ValidatedTimeKey] = timeProvider.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        properties.Items[Authentication.AuthenticationServiceCollectionExtensions.ValidatedIssuerStateKey] = Options.Issuer;
        return HandleRequestResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Scheme.Name));
    }

    async Task<bool> IsWithinLimits(C.CodeSignIn settings, string address)
    {
        var throttle = settings.Throttle;
        var client = locations.Resolve(Context).IpAddress;
        if (!await store.TryCount($"{Scheme.Name}|address|{address}", throttle.PerAddress, throttle.Window))
        {
            _logger.CodeRequestThrottled("address");
            return false;
        }

        if (!await store.TryCount($"{Scheme.Name}|client|{client}", throttle.PerClient, throttle.Window))
        {
            _logger.CodeRequestThrottled("client");
            return false;
        }

        return true;
    }
}
