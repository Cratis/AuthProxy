// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// Represents what a service's answer on <c>/.cratis/me</c> means to AuthProxy.
/// </summary>
/// <remarks>
/// Mirrors the AuthProxy configuration enumeration of the same name. The member names are what is written
/// to the environment variable, so they have to stay in step with it.
/// </remarks>
public enum IdentityVerificationMode
{
    /// <summary>
    /// The endpoint enriches identity details. Any answer that is not an explicit <c>403</c> lets the
    /// request through, including an unreachable service, a timeout, another non-success status, an empty
    /// body and an unparseable body. This is the released behavior and the default.
    /// </summary>
    BestEffort = 0,

    /// <summary>
    /// The endpoint is an authorization decision. Only an explicit positive lets the request through, and
    /// every other outcome denies it and clears any remembered authorization.
    /// </summary>
    Required = 1
}
