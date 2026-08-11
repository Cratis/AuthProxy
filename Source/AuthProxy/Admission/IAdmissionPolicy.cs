// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Defines the policy deciding whether a request is answered at all.
/// </summary>
public interface IAdmissionPolicy
{
    /// <summary>
    /// Determines whether the configuration closes the interactive contract.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when admission gates the deployment; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Nothing configured is the state every deployment that never opts in is in, and it has to stay
    /// indistinguishable from this feature not existing. Asking first keeps every other question — the
    /// cookie, its protection, its expiry — off the path of a deployment that does not use it.
    /// <para>
    /// The question is asked as "is this deployment public", not as "is this deployment capability-only",
    /// so that a mode nobody here recognizes closes the contract instead of opening it. A number outside the
    /// enum binds without complaint, and the equality form would have read it as neither mode and left the
    /// gate inert — a deployment that asked to be closed, silently answering everybody.
    /// </para>
    /// </remarks>
    bool IsConfigured(C.AuthProxy config);

    /// <summary>
    /// Determines whether a request is the one place a capability may be presented.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when the request targets the admission endpoint exactly; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Exactly, not by prefix. Anything below the configured path is an ordinary unadmitted request, so a
    /// capability smuggled into a path segment is refused the same way an absent one is.
    /// </remarks>
    bool IsPresentation(HttpContext context, C.AuthProxy config);

    /// <summary>
    /// Determines whether the caller on the current request has been admitted.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>, carrying whatever the browser presented.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when the request may proceed; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A missing entry transaction is <em>not</em> permission. That is worth stating because the neighboring
    /// invitation binding deliberately answers the opposite — it relaxes when there is nothing to bind — and
    /// borrowing that shape here would leave a gate that admits everyone while every happy-path spec still
    /// passes.
    /// </remarks>
    bool IsAdmitted(HttpContext context, C.AuthProxy config);

    /// <summary>
    /// Determines whether the client-credentials token endpoint is part of this deployment's routing table.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when the endpoint should be mapped; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// The endpoint is mapped unconditionally today, including for deployments where no service declares
    /// client credentials and it can therefore only ever refuse — which still confirms that an AuthProxy is
    /// what is answering. A closed deployment that has no use for it does not get one; every other
    /// deployment keeps it, because removing it outright would be a breaking change.
    /// <para>
    /// "Every other deployment" means <see cref="C.AdmissionMode.Public"/> specifically, for the same reason
    /// <see cref="IsConfigured"/> asks it that way: an unrecognized mode must not be the one value that hands
    /// a closed deployment an endpoint back.
    /// </para>
    /// </remarks>
    bool DeclaresTokenEndpoint(C.AuthProxy config);
}
