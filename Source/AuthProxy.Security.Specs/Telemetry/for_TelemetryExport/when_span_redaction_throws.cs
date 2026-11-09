// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace Cratis.AuthProxy.Security.Telemetry.for_TelemetryExport;

public class when_span_redaction_throws : given.an_export_pipeline
{
    void Because()
    {
        using var activity = Source.StartActivity("request", ActivityKind.Server)!;

        // PathString rejects a path without a leading slash, after other attributes were redacted.
        activity.SetTag("url.path", SensitiveValue)
            .SetTag("http.target", SensitiveUrl)
            .SetTag("unrecognized.attribute", SensitiveValue)
            .AddException(new HttpRequestException(SensitiveUrl));
    }

    [Fact] public void should_still_export_the_span() => Assert.Single(Activities);
    [Fact] public void should_discard_all_attributes_instead_of_exporting_partial_redaction() => Assert.Empty(Assert.Single(Activities).TagObjects);
    [Fact] public void should_still_remove_exception_details() => Assert.Empty(Assert.Single(Assert.Single(Activities).Events).Tags);
}
