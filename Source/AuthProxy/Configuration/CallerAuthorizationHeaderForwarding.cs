// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents whether the <c language="text">Authorization</c> header a caller sent reaches a service.
/// </summary>
/// <remarks>
/// This concerns only a header the caller sent. A token AuthProxy obtains for the service with
/// <see cref="Service.AccessToken"/>, and the bearer token of a caller that AuthProxy itself authenticated, are always
/// forwarded.
/// </remarks>
public enum CallerAuthorizationHeaderForwarding
{
    /// <summary>
    /// The caller's header is removed from requests authenticated by the AuthProxy session, and kept on requests that
    /// carry no session, such as those to an anonymous path.
    /// </summary>
    Default = 0,

    /// <summary>
    /// The caller's header is forwarded on every request, including those authenticated by the AuthProxy session.
    /// </summary>
    Forward = 1,

    /// <summary>
    /// The caller's header is removed from every request the service receives, unless AuthProxy itself authenticated the
    /// caller with that bearer token.
    /// </summary>
    Strip = 2
}
