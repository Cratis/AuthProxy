// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Diagnostics;
using Cratis.AuthProxy.Telemetry;
using Cratis.Specifications;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Trace;

namespace Cratis.AuthProxy.Security.Telemetry.for_TelemetryExport.given;

public class an_export_pipeline : Specification
{
    protected const string SensitiveValue = "tenant-private-c0ffee";
    protected const string SensitiveUrl = "https://tenant-private-c0ffee.example/identity?code=private-code";
    protected readonly ConcurrentQueue<Activity> Activities = new();
    protected readonly ConcurrentQueue<string> Logs = new();
    protected WebApplication Application;
    protected ActivitySource Source;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://127.0.0.1:1";
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Debug);
        builder.AddTelemetry();
        var sourceName = $"TelemetryExportSpecs.{Guid.NewGuid()}";
        Source = new ActivitySource(sourceName);
        builder.Services.ConfigureOpenTelemetryTracerProvider(provider => provider
            .AddSource(sourceName)
            .AddProcessor(new SimpleActivityExportProcessor(new ActivityExporter(Activities, sourceName))));
        builder.Services.ConfigureOpenTelemetryLoggerProvider(provider => provider
            .AddProcessor(new SimpleLogRecordExportProcessor(new LogExporter(Logs))));
        Application = builder.Build();
        _ = Application.Services.GetRequiredService<TracerProvider>();
    }

    async Task Destroy()
    {
        Source.Dispose();
        await Application.DisposeAsync();
    }

    sealed class ActivityExporter(ConcurrentQueue<Activity> activities, string sourceName) : BaseExporter<Activity>
    {
        public override ExportResult Export(in Batch<Activity> batch)
        {
            foreach (var activity in batch)
            {
                if (activity.Source.Name == sourceName || activity.Parent?.Source.Name == sourceName)
                {
                    activities.Enqueue(activity);
                }
            }

            return ExportResult.Success;
        }
    }

    sealed class LogExporter(ConcurrentQueue<string> logs) : BaseExporter<LogRecord>
    {
        public override ExportResult Export(in Batch<LogRecord> batch)
        {
            foreach (var record in batch)
            {
                logs.Enqueue(string.Join('\n', record.CategoryName, record.Body, record.FormattedMessage, record.Exception, string.Join(';', (record.Attributes ?? []).Select(tag => $"{tag.Key}={tag.Value}"))));
            }

            return ExportResult.Success;
        }
    }
}
