// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;
using OpenTelemetry;

namespace Cratis.AuthProxy.Telemetry;

/// <summary>
/// Sanitizes completed activities before any exporter can queue them.
/// </summary>
internal sealed class TelemetryActivityProcessor : BaseProcessor<Activity>
{
    /// <inheritdoc/>
    public override void OnEnd(Activity data)
    {
        try
        {
            TelemetryRedaction.Redact(data);
        }
        catch (Exception)
        {
            // A malformed path must not turn an enrichment failure into an unredacted export.
            // Discard every attribute rather than trying to interpret the failed input again.
            foreach (var tag in data.TagObjects.ToArray())
            {
                data.SetTag(tag.Key, null);
            }
        }

        data.SetStatus(data.Status);
        foreach (var tag in data.TagObjects.Where(tag => tag.Key.StartsWith("exception.", StringComparison.Ordinal)).ToArray())
        {
            data.SetTag(tag.Key, null);
        }

        // The public ref enumerator lets us replace immutable events before exporter queuing.
        // Keep names and timestamps, but never exception details (including native HttpClient events).
        foreach (ref var activityEvent in data.EnumerateEvents())
        {
            var tags = activityEvent.Name == "exception"
                ? null
                : new ActivityTagsCollection(activityEvent.Tags.Where(tag => !tag.Key.StartsWith("exception.", StringComparison.Ordinal)));
            activityEvent = new ActivityEvent(activityEvent.Name, activityEvent.Timestamp, tags);
        }
    }
}
