// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityBody.given;

/// <summary>
/// A stream that remembers how much of it was actually read.
/// </summary>
/// <param name="length">How many bytes it can produce.</param>
/// <remarks>
/// The bound on a capability body is not a validation rule but a limit on what a caller admitted to
/// nothing can make this process hold, so the property worth specifying is not "an oversized body is
/// refused" — it is that the bytes beyond the bound were never read. Only the stream can say that.
/// </remarks>
public sealed class CountingStream(int length) : Stream
{
    int _position;

    /// <summary>
    /// Gets how many bytes were read from the stream.
    /// </summary>
    public int BytesRead { get; private set; }

    /// <inheritdoc/>
    public override bool CanRead => true;

    /// <inheritdoc/>
    public override bool CanSeek => false;

    /// <inheritdoc/>
    public override bool CanWrite => false;

    /// <inheritdoc/>
    public override long Length => length;

    /// <inheritdoc/>
    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    /// <inheritdoc/>
    public override void Flush()
    {
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count)
    {
        var available = Math.Min(count, length - _position);
        if (available <= 0)
        {
            return 0;
        }

        // One byte at a time, so a reader asking for more than the bound cannot be handed it by accident.
        available = Math.Min(available, 64);
        Array.Fill(buffer, (byte)'a', offset, available);
        _position += available;
        BytesRead += available;

        return available;
    }

    /// <inheritdoc/>
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc/>
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
