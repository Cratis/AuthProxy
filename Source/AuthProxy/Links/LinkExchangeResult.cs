// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Represents the outcome of posting a freshly authenticated subject to the application's link-exchange endpoint.
/// </summary>
public enum LinkExchangeResult
{
    /// <summary>The subject was recorded by the application successfully.</summary>
    Success = 0,

    /// <summary>The exchange could not be performed or was rejected by the application.</summary>
    Failed = 1,
}
