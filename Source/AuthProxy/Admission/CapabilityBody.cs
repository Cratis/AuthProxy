// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Reads a presented capability from a request body under a hard bound.
/// </summary>
/// <remarks>
/// The caller presenting it has been admitted to nothing, so the bound is not a validation rule but the
/// limit on what an unadmitted caller can make this process hold. Nothing beyond it is ever read into
/// memory: a declared length above the bound is refused before the body is touched at all, and an
/// undeclared one is read only far enough to establish that it exceeds the bound.
/// </remarks>
public static class CapabilityBody
{
    /// <summary>
    /// Reads the capability from a request, or refuses it.
    /// </summary>
    /// <param name="request">The request carrying the presentation.</param>
    /// <param name="maximumLength">The largest capability, in bytes, that will be read.</param>
    /// <param name="cancellationToken">The token that aborts the read.</param>
    /// <returns>The capability, or <see langword="null"/> when the body is absent, empty or over the bound.</returns>
    public static async Task<string?> TryRead(HttpRequest request, int maximumLength, CancellationToken cancellationToken)
    {
        if (request.ContentLength is long declared && declared > maximumLength)
        {
            return null;
        }

        return await TryRead(request.Body, maximumLength, cancellationToken);
    }

    /// <summary>
    /// Reads the capability from a stream, or refuses it.
    /// </summary>
    /// <param name="body">The stream carrying the presentation.</param>
    /// <param name="maximumLength">The largest capability, in bytes, that will be read.</param>
    /// <param name="cancellationToken">The token that aborts the read.</param>
    /// <returns>The capability, or <see langword="null"/> when the body is absent, empty or over the bound.</returns>
    /// <remarks>
    /// One byte beyond the bound is read, and only one: it is what distinguishes a body that exactly fills
    /// the bound from one that overruns it, and there is no way to tell them apart without it.
    /// </remarks>
    public static async Task<string?> TryRead(Stream body, int maximumLength, CancellationToken cancellationToken)
    {
        if (maximumLength <= 0)
        {
            return null;
        }

        var buffer = new byte[maximumLength + 1];
        var read = 0;

        while (read < buffer.Length)
        {
            var count = await body.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (count == 0)
            {
                break;
            }

            read += count;
        }

        if (read == 0 || read > maximumLength)
        {
            return null;
        }

        var capability = Encoding.UTF8.GetString(buffer, 0, read).Trim();

        return string.IsNullOrEmpty(capability) ? null : capability;
    }
}
