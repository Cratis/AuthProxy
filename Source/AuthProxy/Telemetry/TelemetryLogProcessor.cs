// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using OpenTelemetry;
using OpenTelemetry.Logs;

namespace Cratis.AuthProxy.Telemetry;

/// <summary>
/// Exports log metadata only, leaving the original diagnostic details with local logging providers.
/// </summary>
internal sealed class TelemetryLogProcessor : BaseProcessor<LogRecord>
{
    /// <inheritdoc/>
    public override void OnEnd(LogRecord data)
    {
        // A template or a formatted message may contain identifiers even without scopes. An
        // exception can also embed a URL. Do not attempt to recognize every sensitive value.
        data.Body = "Log details redacted";
        data.FormattedMessage = "Log details redacted";
        data.Attributes = [];
        data.Exception = null;
    }
}
