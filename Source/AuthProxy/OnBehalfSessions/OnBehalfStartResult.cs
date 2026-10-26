// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the result of an attempt to start an on-behalf session.
/// </summary>
/// <param name="Status">How the attempt ended.</param>
/// <param name="Session">The session, when it started.</param>
/// <param name="Grant">The grant it started under, when it started.</param>
public sealed record OnBehalfStartResult(OnBehalfStartStatus Status, OnBehalfSession? Session = null, OnBehalfGrant? Grant = null);
