// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Releases the flows AuthProxy answers itself from the route the reverse proxy selected for them, so the
/// middleware that owns each flow is what answers it.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <remarks>
/// <see cref="IngressExtensions.UseIngress"/> anchors endpoint matching at <c>UseRouting</c>, and YARP's
/// catch-all route matches every path — including the two prefixes that are reserved from every service
/// precisely because no service ever serves them. Those routes are generated with the default authorization
/// policy, which is <c>RequireAuthenticatedUser</c>, so <c>UseAuthorization</c> refused an invitation or a
/// registration before <see cref="Invites.InviteMiddleware"/> or
/// <see cref="Registrations.RegistrationMiddleware"/> — both registered after it — could run at all. The
/// visible symptom was an invitation link that answered with provider selection and no pending-invitation
/// cookie: the sign-in that followed carried no capability binding, so the callback had nothing to complete
/// and the person was offered provider selection a second time, the first pass having finally planted the
/// cookie the second one needed.
/// <para>
/// The endpoint is cleared rather than the authorization step skipped. Skipping it would leave the
/// catch-all's authorization metadata on a request that never evaluated it, which
/// <c>EndpointMiddleware</c> refuses outright; clearing it removes the claim on the path instead, leaving
/// <c>UseAuthorization</c> to find nothing to enforce and pass the request on. That says what is true —
/// these paths belong to the proxy, not to a route — and makes it impossible for one to be proxied to a
/// backend by a route that matched it only for want of a more specific one.
/// </para>
/// <para>
/// Nothing else is relaxed. Both flows re-validate their own capability — signature, issuer, audience and
/// lifetime — on every phase, and <see cref="Identity.IdentityForwardingGuardMiddleware"/> remains the
/// fail-closed backstop that no request reaches a service without a forwardable identity.
/// </para>
/// </remarks>
public class ProxyOwnedFlowMiddleware(RequestDelegate next)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.IsProxyOwnedFlow())
        {
            context.SetEndpoint(null);
        }

        await next(context);
    }
}
