// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Middleware that answers nothing to a caller the deployment has not admitted.
/// </summary>
/// <remarks>
/// It runs first — after the forwarded headers are applied, so the request describes its real origin, and
/// before the pages map, the static files, routing, authentication and everything downstream of them. That
/// ordering is the whole feature: <c>/_pages</c> and the bundled assets are served ahead of authentication
/// by design, so a gate placed anywhere later would leave them public no matter what it decided.
/// <para>
/// Nothing else about the pipeline moves. <c>UseRouting()</c> in particular stays exactly where it is, for
/// the reason recorded beside it: moving it once made every bundled asset answer <c>401</c>.
/// </para>
/// <para>
/// A deployment in <see cref="C.AdmissionMode.Public"/> leaves this on the first line of
/// <see cref="InvokeAsync"/> and never touches the request again.
/// </para>
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="policy">The policy deciding whether the caller has been admitted.</param>
/// <param name="admission">The handler turning a presented capability into an entry.</param>
public class AdmissionMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    IAdmissionPolicy policy,
    ICapabilityAdmission admission)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var current = config.CurrentValue;

        if (!policy.IsConfigured(current))
        {
            await next(context);
            return;
        }

        if (policy.IsPresentation(context, current))
        {
            if (!await admission.TryAdmit(context, current))
            {
                await UniformDenial.Write(context);
            }

            return;
        }

        if (policy.IsAdmitted(context, current))
        {
            await next(context);
            return;
        }

        await UniformDenial.Write(context);
    }
}
