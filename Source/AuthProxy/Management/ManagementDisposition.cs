// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Represents what the management listener does with a request.
/// </summary>
public enum ManagementDisposition
{
    /// <summary>
    /// The request is none of the management listener's business and continues down the ingress pipeline.
    /// </summary>
    Continue = 0,

    /// <summary>
    /// Answer liveness.
    /// </summary>
    Live = 1,

    /// <summary>
    /// Answer readiness.
    /// </summary>
    Ready = 2,

    /// <summary>
    /// Answer the uniform not-found, and go no further.
    /// </summary>
    Refuse = 3
}
