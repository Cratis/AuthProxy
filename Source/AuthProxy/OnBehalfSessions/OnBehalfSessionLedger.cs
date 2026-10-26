// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Remembers, per AuthProxy instance, the grant answers that are still fresh and the sessions that have ended.
/// </summary>
/// <param name="timeProvider">The source of the current time.</param>
/// <remarks>
/// The grant cache is what bounds the cost of re-checking: a live answer is trusted until the earliest of the
/// re-check interval, the grant's own <c language="text">validUntil</c> and the session's expiry, and asked about again after
/// that. The ended set keeps a copied cookie of an ended session from being used again on this instance; across
/// instances the application's grant check is what refuses it, which is why the session identifier is sent with
/// every check. Nothing here is keyed by anything but the random session identifier, and every entry is dropped
/// once it can no longer matter.
/// </remarks>
public sealed class OnBehalfSessionLedger(TimeProvider timeProvider)
{
    readonly ConcurrentDictionary<string, (OnBehalfGrant Grant, DateTimeOffset Until)> _grants = new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<string, (OnBehalfSessionEndReason Reason, DateTimeOffset Until)> _ended = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the current time.
    /// </summary>
    public DateTimeOffset Now => timeProvider.GetUtcNow();

    /// <summary>
    /// Gets a grant answer that is still fresh.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="grant">The remembered grant.</param>
    /// <returns><see langword="true"/> when a fresh answer is remembered; otherwise <see langword="false"/>.</returns>
    public bool TryGetGrant(string sessionId, out OnBehalfGrant grant)
    {
        grant = OnBehalfGrant.Indeterminate;
        if (!_grants.TryGetValue(sessionId, out var entry))
        {
            return false;
        }

        if (entry.Until <= Now)
        {
            _grants.TryRemove(sessionId, out _);
            return false;
        }

        grant = entry.Grant;
        return true;
    }

    /// <summary>
    /// Remembers a live grant answer until it must be asked about again.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="grant">The live grant.</param>
    /// <param name="until">When the answer stops being fresh.</param>
    public void Remember(string sessionId, OnBehalfGrant grant, DateTimeOffset until)
    {
        Purge();
        _grants[sessionId] = (grant, until);
    }

    /// <summary>
    /// Records that a session ended.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="reason">Why it ended.</param>
    /// <param name="until">How long the record must be kept: the session's expiry.</param>
    /// <returns><see langword="true"/> when this call ended it; <see langword="false"/> when it had already ended.</returns>
    public bool TryMarkEnded(string sessionId, OnBehalfSessionEndReason reason, DateTimeOffset until)
    {
        Purge();
        _grants.TryRemove(sessionId, out _);
        return _ended.TryAdd(sessionId, (reason, until));
    }

    /// <summary>
    /// Determines whether a session has ended on this instance.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="reason">Why it ended.</param>
    /// <returns><see langword="true"/> when it has ended; otherwise <see langword="false"/>.</returns>
    public bool HasEnded(string sessionId, out OnBehalfSessionEndReason reason)
    {
        reason = default;
        if (!_ended.TryGetValue(sessionId, out var entry))
        {
            return false;
        }

        reason = entry.Reason;
        return true;
    }

    void Purge()
    {
        var now = Now;
        foreach (var expired in _grants.Where(_ => _.Value.Until <= now).Select(_ => _.Key).ToArray())
        {
            _grants.TryRemove(expired, out _);
        }

        foreach (var expired in _ended.Where(_ => _.Value.Until <= now).Select(_ => _.Key).ToArray())
        {
            _ended.TryRemove(expired, out _);
        }
    }
}
