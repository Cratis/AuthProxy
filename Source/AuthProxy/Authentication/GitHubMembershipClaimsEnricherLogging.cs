// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

internal static partial class GitHubMembershipClaimsEnricherLogging
{
    [LoggerMessage(LogLevel.Warning, "GitHub membership read of {Resource} answered {StatusCode}. Signing in without the membership claims it would have added.")]
    internal static partial void MembershipReadFailed(this ILogger logger, string resource, int statusCode);

    [LoggerMessage(LogLevel.Warning, "GitHub membership read of {Resource} could not be completed. Signing in without the membership claims it would have added.")]
    internal static partial void MembershipReadUnavailable(this ILogger logger, string resource, Exception exception);

    [LoggerMessage(LogLevel.Warning, "GitHub membership read of {Resource} returned something that could not be read as JSON. Signing in without the membership claims it would have added.")]
    internal static partial void MembershipReadUnreadable(this ILogger logger, string resource, Exception exception);

    [LoggerMessage(LogLevel.Warning, "The UserInformationEndpoint configured for provider '{Provider}' is not an absolute URL, so its membership endpoints cannot be resolved. No membership claims are added.")]
    internal static partial void MembershipEndpointUnresolvable(this ILogger logger, string provider);
}
