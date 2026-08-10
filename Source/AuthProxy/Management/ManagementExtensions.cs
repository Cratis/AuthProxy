// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Management;

/// <summary>
/// Extension methods for opening the private management listener on <see cref="WebApplicationBuilder"/>
/// and placing it on the pipeline of a <see cref="WebApplication"/>.
/// </summary>
public static class ManagementExtensions
{
    /// <summary>
    /// Declares the private management listener when the deployment configured one.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    /// <remarks>
    /// Without a management section this changes nothing: no additional address is declared, no additional
    /// socket is opened, and the process binds exactly what it binds today.
    /// <para>
    /// ⚠️ The listener is added by <em>re-declaring</em> the host's addresses, never with
    /// <c>ConfigureKestrel(options =&gt; options.Listen(...))</c>. Populating
    /// <c>KestrelServerOptions.ListenOptions</c> makes Kestrel discard the hosting addresses entirely
    /// whenever <c>PreferHostingUrls</c> is left at its default of <see langword="false"/> — it logs
    /// "Overriding address(es)" and binds only what was passed to <c>Listen</c>. The public listener of
    /// every containerized deployment comes from those hosting addresses, so an opt-in health endpoint
    /// would take the whole proxy off the network. Both listeners have to come from the same place, and
    /// the public one is already in the addresses.
    /// </para>
    /// </remarks>
    public static WebApplicationBuilder AddManagement(this WebApplicationBuilder builder)
    {
        // Resolved and registered before anything is changed, so the validator compares the requested port
        // against the addresses as they were rather than against the one this method is about to add.
        var listeners = ListenerAddresses.Resolve(builder.Configuration);
        builder.Services.AddSingleton(listeners);
        builder.Services.AddSingleton<IValidateOptions<C.AuthProxy>, ManagementConfigurationValidator>();

        var management = ReadSection(builder.Configuration);
        if (management?.Port is null)
        {
            return builder;
        }

        builder.Services.AddSingleton<IReadinessCheck, DataProtectionReadiness>();

        // Kestrel names itself on every response it writes, and whether it does is a per-server setting
        // rather than a per-listener one. A management endpoint must describe nothing about what is
        // running it, so enabling the listener also stops AuthProxy advertising its server on the public
        // one. This touches no ListenOptions and is therefore not the trap described above.
        builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

        builder.WebHost.UseUrls([.. listeners.Including(UrlFor(management))]);

        return builder;
    }

    /// <summary>
    /// Places the management listener's endpoints and its isolation on the pipeline.
    /// </summary>
    /// <param name="app">The <see cref="WebApplication"/> to configure.</param>
    /// <returns>The same <see cref="WebApplication"/> for chaining.</returns>
    /// <remarks>
    /// Belongs first, ahead of every ingress middleware. A request arriving on the management port must
    /// never be seen by authentication, tenancy, the anonymous-path policy or the reverse proxy, and a
    /// health answer must not acquire a challenge header or a session cookie on its way out.
    /// <para>
    /// Without a management section this adds nothing to the pipeline at all.
    /// </para>
    /// </remarks>
    public static WebApplication UseManagement(this WebApplication app)
    {
        var management = ReadSection(app.Configuration);
        if (management?.Port is null)
        {
            return app;
        }

        var isolation = new ManagementListenerIsolation(management.Port.Value, management.LivePath, management.ReadyPath);
        var endpoints = new ManagementEndpoints(app.Services.GetRequiredService<IReadinessCheck>());

        app.Use(async (context, next) =>
        {
            var disposition = isolation.Decide(context);
            if (disposition == ManagementDisposition.Continue)
            {
                await next(context);
                return;
            }

            await endpoints.Answer(context, disposition);
        });

        return app;
    }

    static C.Management? ReadSection(IConfiguration configuration) =>
        configuration.GetSection(ManagementConfigurationValidator.SectionKey).Get<C.Management>();

    static string UrlFor(C.Management management) =>
        $"http://{management.BindAddress}:{management.Port!.Value.ToString(CultureInfo.InvariantCulture)}";
}
