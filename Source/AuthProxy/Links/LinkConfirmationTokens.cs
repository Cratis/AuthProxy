// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

/// <summary>
/// The substitution tokens of the link confirmation page.
/// </summary>
public static class LinkConfirmationTokens
{
    /// <summary>
    /// Receives the path the confirmation form posts to.
    /// </summary>
    public const string Action = "__CRATIS_LINK_ACTION__";

    /// <summary>
    /// Receives the display name of the provider being linked.
    /// </summary>
    public const string Provider = "__CRATIS_LINK_PROVIDER__";

    /// <summary>
    /// Receives the one-time link token carried by the form.
    /// </summary>
    public const string Token = "__CRATIS_LINK_TOKEN__";

    /// <summary>
    /// Receives the return URL carried by the form.
    /// </summary>
    public const string ReturnUrl = "__CRATIS_LINK_RETURN_URL__";

    /// <summary>
    /// Receives the name of the antiforgery form field.
    /// </summary>
    public const string FieldName = "__CRATIS_LINK_ANTIFORGERY_FIELD__";

    /// <summary>
    /// Receives the antiforgery request token.
    /// </summary>
    public const string RequestToken = "__CRATIS_LINK_ANTIFORGERY_TOKEN__";
}
