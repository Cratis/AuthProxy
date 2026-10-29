// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Defers resource disposal until admitted operations and shutdown cancellation callbacks have unwound.
/// </summary>
internal sealed class InvitationTokenKeysLifetime
{
    readonly Lock _gate = new();
    Action? _disposeResources;
    int _active;
    bool _stopping;

    /// <summary>Gets whether admission has stopped.</summary>
    internal bool IsStopping
    {
        get
        {
            lock (_gate)
            {
                return _stopping;
            }
        }
    }

    /// <summary>Admits a foreground operation or refuses work after shutdown begins.</summary>
    internal void Enter() => ObjectDisposedException.ThrowIf(!TryEnter(), this);

    /// <summary>Attempts to admit background work before shutdown begins.</summary>
    /// <returns>Whether the operation now owns a lifetime reservation.</returns>
    internal bool TryEnter()
    {
        lock (_gate)
        {
            if (_stopping)
            {
                return false;
            }
            _active++;
            return true;
        }
    }

    /// <summary>Releases an operation, disposing resources only when shutdown has drained.</summary>
    internal void Exit()
    {
        Action? disposeResources;
        lock (_gate)
        {
            _active--;
            disposeResources = _stopping && _active == 0 ? _disposeResources : null;
        }
        disposeResources?.Invoke();
    }

    /// <summary>Stops admission and requests cancellation without waiting for asynchronous operations.</summary>
    /// <param name="cancel">The shutdown cancellation to request while resources are still reserved.</param>
    /// <param name="disposeResources">The cleanup to run after every operation has unwound.</param>
    /// <returns>Whether the caller can dispose resources immediately; otherwise the last operation will dispose them.</returns>
    internal bool Stop(Action cancel, Action disposeResources)
    {
        lock (_gate)
        {
            if (_stopping)
            {
                return false;
            }
            _stopping = true;
            _disposeResources = disposeResources;

            // Cancellation callbacks must also finish before the source and gates can be disposed.
            _active++;
        }
        try
        {
            cancel();
        }
        catch
        {
            Exit();
            throw;
        }
        lock (_gate)
        {
            _active--;
            return _active == 0;
        }
    }
}
