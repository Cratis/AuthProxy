// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// The exception that is thrown when an on-behalf request is about to be forwarded and its assertion cannot be
/// issued. The request is never sent without one.
/// </summary>
/// <param name="reason">Why the assertion could not be issued.</param>
public class OnBehalfAssertionCouldNotBeIssued(string reason)
    : Exception($"The on-behalf assertion could not be issued, so the request is not forwarded: {reason}");
