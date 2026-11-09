// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Carries a bounded freshness request through protected provider state.</summary>
internal static class FreshAuthenticationChallenge
{
    /// <summary>The query hint requesting reauthentication.</summary>
    internal const string QueryKey = "fresh";

    /// <summary>The bounded age hint carried by the login page.</summary>
    internal const string MaxAgeQueryKey = "maxAge";

    /// <summary>The freshness requirement inside protected remote state.</summary>
    internal const string PropertyKey = ".cratis.fresh.max-age";

    /// <summary>The authentication time obtained from a validated identity token.</summary>
    internal const string ValidatedTimeKey = ".cratis.fresh.validated-time";

    /// <summary>Reads the injected clock, with the system clock as the default.</summary>
    /// <param name="context">The request context.</param>
    /// <returns>The current time.</returns>
    internal static DateTimeOffset Now(HttpContext context) => (context.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow();

    /// <summary>Recognizes the explicit reauthentication hint.</summary>
    /// <param name="context">The request context.</param>
    /// <returns>Whether reauthentication was requested.</returns>
    internal static bool Requested(HttpContext context) => context.Request.Query[QueryKey] == "1";

    /// <summary>Copies bounded hints into protected challenge properties.</summary>
    /// <param name="context">The request context.</param>
    /// <param name="properties">The protected challenge properties.</param>
    internal static void Apply(HttpContext context, AuthenticationProperties properties)
    {
        if (Requested(context))
        {
            var requested = context.Request.Query[MaxAgeQueryKey].ToString();
            properties.Items[PropertyKey] = int.TryParse(requested, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds is >= 1 and <= 86400 ? requested : "300";
        }
    }

    /// <summary>Reads the bounded maximum age from protected state.</summary>
    /// <param name="properties">The protected challenge properties.</param>
    /// <param name="age">The requested maximum age.</param>
    /// <returns>Whether a bounded age was recorded.</returns>
    internal static bool TryGetMaxAge(AuthenticationProperties properties, out TimeSpan age)
    {
        age = default;
        if (!properties.Items.TryGetValue(PropertyKey, out var value)
            || !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            || seconds is < 1 or > 86400)
        {
            return false;
        }
        age = TimeSpan.FromSeconds(seconds);
        return true;
    }

    /// <summary>Checks signed authentication time for a marked OIDC completion.</summary>
    /// <param name="validatedClaims">Claims from the framework-validated identity token.</param>
    /// <param name="properties">The protected challenge properties.</param>
    /// <param name="now">The current time.</param>
    /// <returns>Whether the completion satisfies any requested freshness requirement.</returns>
    internal static bool ValidateOidc(IEnumerable<Claim> validatedClaims, AuthenticationProperties properties, DateTimeOffset now)
    {
        var claims = validatedClaims.Where(_ => _.Type == "auth_time").ToArray();
        var time = default(DateTimeOffset);
        var valid = claims.Length == 1 && SessionAuthenticationTime.TryParse(claims[0].Value, out time);

        // Only a time the validated token proves is ever recorded; callback time is never a substitute, because a
        // provider that reuses its own session would make a stale authentication look fresh.
        if (properties.Items.ContainsKey(PropertyKey)
            && (!TryGetMaxAge(properties, out var age) || !valid || time > now || now - time > age))
        {
            return false;
        }
        if (valid && time <= now)
        {
            properties.Items[ValidatedTimeKey] = time.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        }
        return true;
    }

    /// <summary>
    /// Records the authentication time a validated OIDC token proved. Records nothing otherwise: an OAuth provider
    /// can neither prove nor force when the user authenticated, and an unproven time is unknown.
    /// </summary>
    /// <param name="principal">The completed principal.</param>
    /// <param name="properties">The protected session properties.</param>
    /// <param name="oidc">Whether a validated OIDC authentication time may be used.</param>
    internal static void Stamp(ClaimsPrincipal principal, AuthenticationProperties properties, bool oidc)
    {
        var time = default(DateTimeOffset);
        var proven = oidc && properties.Items.TryGetValue(ValidatedTimeKey, out var value) && SessionAuthenticationTime.TryParse(value, out time);
        properties.Items.Remove(ValidatedTimeKey);
        properties.Items.Remove(PropertyKey);
        properties.Items.Remove(SessionAuthenticationTime.PropertyKey);
        if (proven)
        {
            SessionAuthenticationTime.Stamp(principal, properties, time);
        }
    }

    /// <summary>Builds a retry link; the original operation is never replayed.</summary>
    /// <param name="scheme">The recorded provider, or null for provider selection.</param>
    /// <param name="returnUrl">The relative destination after authentication.</param>
    /// <param name="maxAge">The maximum authentication age.</param>
    /// <returns>The login URL.</returns>
    internal static string Login(string? scheme, string returnUrl, TimeSpan? maxAge = null) => QueryHelpers.AddQueryString(
        scheme is null ? WellKnownPaths.LoginPage : $"{WellKnownPaths.LoginPrefix}/{scheme}",
        new Dictionary<string, string?> { [QueryKey] = "1", ["returnUrl"] = returnUrl, [MaxAgeQueryKey] = ((int)(maxAge ?? TimeSpan.FromMinutes(5)).TotalSeconds).ToString(CultureInfo.InvariantCulture) });

    /// <summary>Preserves freshness across a callback-host bounce.</summary>
    /// <param name="context">The request context.</param>
    /// <param name="query">The bounce query parameters.</param>
    internal static void Preserve(HttpContext context, IDictionary<string, string?> query)
    {
        if (Requested(context))
        {
            var properties = new AuthenticationProperties();
            Apply(context, properties);
            query[QueryKey] = "1";
            query[MaxAgeQueryKey] = properties.Items[PropertyKey];
        }
    }

    /// <summary>Ends a stale OIDC completion with an explicit retry page.</summary>
    /// <param name="context">The request context.</param>
    /// <param name="properties">The protected challenge properties.</param>
    internal static void Reject(HttpContext context, AuthenticationProperties properties)
    {
        TransientAuthenticationCookies.Clear(context);
        TryGetMaxAge(properties, out var maxAge);
        var location = Login(null, RelativeRedirect.Resolve(properties.RedirectUri), maxAge == default ? null : maxAge);
        context.Response.Redirect(QueryHelpers.AddQueryString(location, SignInFailureReason.QueryKey, SignInFailureReason.FreshAuthenticationRequired));
    }
}
