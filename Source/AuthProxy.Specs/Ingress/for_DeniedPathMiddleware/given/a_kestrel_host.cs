// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Ingress.for_DeniedPathMiddleware.given;

public class a_kestrel_host : IAsyncLifetime
{
    WebApplication _app;

    public async ValueTask InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        builder.Services.Configure<C.Ingress>(options => options.DeniedPathPrefixes = ["/internal/"]);
        _app = builder.Build();
        _app.UseDeniedPathPrefixes();
        _app.UseRouting();
        _app.MapGet("/x", ServeX);
        _app.MapFallback("{**path}", (HttpContext context, string? path) => Serve(context));
        await _app.StartAsync(TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync(TestContext.Current.CancellationToken);
        await _app.DisposeAsync();
    }

    public async Task<string> Request(string target)
    {
        // Send a literal request line: HttpClient's Uri would normalize the target before Kestrel sees it.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, new Uri(_app.Urls.Single()).Port, timeout.Token);
        await using var stream = client.GetStream();
        var request = Encoding.ASCII.GetBytes($"GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request, timeout.Token);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(timeout.Token);
    }

    static Task ServeX(HttpContext context)
    {
        context.Response.Headers["X-Routed-X"] = "true";
        return Serve(context);
    }

    static Task Serve(HttpContext context)
    {
        context.Response.Headers["X-Served-Path"] = context.Request.Path.Value;
        return Task.CompletedTask;
    }
}
