// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Represents the outcome of posting a completed sign-in to the application's sign-in notification endpoint.
/// </summary>
public enum SignInNotificationResult
{
    /// <summary>The sign-in was recorded by the application successfully.</summary>
    Notified = 0,

    /// <summary>No notification URL is configured, so nothing was posted.</summary>
    Skipped = 1,

    /// <summary>The notification could not be performed or was rejected by the application.</summary>
    Failed = 2,
}
