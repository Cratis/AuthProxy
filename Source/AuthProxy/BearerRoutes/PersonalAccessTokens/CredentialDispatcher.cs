// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;

/// <summary>
/// Decides, from the request alone and before any verification, which branch handles the credential it carries.
/// </summary>
/// <remarks>
/// The credential is read once, here, and only the answer travels on: a value in the personal access token
/// namespace (under any scheme) is for the personal access token branch and for nothing else, and every other
/// value is for OAuth validation, where the route accepts it. There is no retry, no second look and no
/// "first header wins": more than one credential refuses the request before either branch is chosen. Nothing
/// here is secret, and nothing here reaches a log — the reason it returns is a fixed phrase.
/// </remarks>
public static class CredentialDispatcher
{
    const string QueryCredentialName = "access_token";
    const string BearerScheme = "Bearer";
    const string ProofOfPossessionScheme = "DPoP";

    /// <summary>
    /// Dispatches the credential on a request.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="route">The route the request was made on.</param>
    /// <returns>The branch that handles the credential, and a log-safe reason for a refusal.</returns>
    public static (CredentialDispatch Dispatch, string Reason) Dispatch(HttpRequest request, ResolvedBearerRoute route)
    {
        var values = request.Headers.Authorization;
        if (values.Count == 0)
        {
            return (CredentialDispatch.Missing, string.Empty);
        }

        if (values.Count > 1 || request.Query.ContainsKey(QueryCredentialName))
        {
            return (CredentialDispatch.Ambiguous, "more than one credential presented");
        }

        var value = values[0] ?? string.Empty;
        var space = value.IndexOf(' ', StringComparison.Ordinal);
        var scheme = space < 0 ? value : value[..space];
        var isBearer = string.Equals(scheme, BearerScheme, StringComparison.OrdinalIgnoreCase);
        var credential = space >= 0 ? value[(space + 1)..] : isBearer ? string.Empty : value;

        if ((isBearer || string.Equals(scheme, ProofOfPossessionScheme, StringComparison.OrdinalIgnoreCase)) && credential.Contains(','))
        {
            return (CredentialDispatch.Ambiguous, "more than one credential presented");
        }

        var shape = PersonalAccessTokenClassifier.Classify(credential);
        return shape.Kind == PersonalAccessTokenKind.NotPersonalAccessToken
            ? DispatchOther(isBearer, route)
            : DispatchPersonalAccessToken(shape, isBearer, route);
    }

    static (CredentialDispatch Dispatch, string Reason) DispatchOther(bool isBearer, ResolvedBearerRoute route)
    {
        if (route.Profile != BearerProfile.PatOnly)
        {
            return (CredentialDispatch.OAuth, string.Empty);
        }

        // Another scheme is not a bearer credential at all, which RFC 6750 answers with a bare challenge.
        return isBearer
            ? (CredentialDispatch.Refused, "the route accepts personal access tokens only")
            : (CredentialDispatch.Missing, string.Empty);
    }

    static (CredentialDispatch Dispatch, string Reason) DispatchPersonalAccessToken(PersonalAccessTokenShape shape, bool isBearer, ResolvedBearerRoute route)
    {
        if (route.Profile == BearerProfile.OAuthOnly)
        {
            return (CredentialDispatch.Refused, "the route does not accept personal access tokens");
        }

        if (!isBearer)
        {
            return (CredentialDispatch.Refused, "a personal access token was not presented as a bearer credential");
        }

        if (shape.Kind != PersonalAccessTokenKind.Canonical)
        {
            return (CredentialDispatch.Refused, "malformed personal access token");
        }

        return string.Equals(shape.ResourceKey, route.ResourceKey, StringComparison.Ordinal)
            ? (CredentialDispatch.PersonalAccessToken, string.Empty)
            : (CredentialDispatch.Refused, "personal access token is for another resource");
    }
}
