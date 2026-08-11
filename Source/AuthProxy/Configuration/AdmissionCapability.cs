// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents where a capability is presented and who decides whether it admits.
/// </summary>
/// <remarks>
/// AuthProxy is deliberately not the authority on what a capability means. It carries the value to the
/// deployment's own verifier and does exactly what the verifier says, so the vocabulary of the thing being
/// presented — who issued it, what it grants, how long it lives, whether it is single use — stays entirely
/// on the deployment's side of the call.
/// </remarks>
public class AdmissionCapability
{
    /// <summary>
    /// Gets or sets the absolute URL of the endpoint that decides whether a presented capability admits.
    /// There is deliberately no default: a verifier is a deployment's own service, and inventing an address
    /// for it would mean a misconfigured deployment silently calling something else.
    /// Leaving it unset while <see cref="AdmissionMode.CapabilityOnly"/> is selected is refused at startup.
    /// </summary>
    public string VerifierUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the one path a capability may be presented on. Every other path — and this path with
    /// anything below it — answers the same refusal as everything else, so nothing this path <em>says</em>
    /// distinguishes it.
    /// </summary>
    /// <remarks>
    /// It is still distinguishable by how long it takes: a presentation here costs a verifier round-trip
    /// that no other path costs. Choosing an unguessable path is therefore worth something and proves
    /// nothing — treat it as one less thing to notice, never as the control.
    /// </remarks>
    public string Path { get; set; } = "/.cratis/admission";

    /// <summary>
    /// Gets or sets the largest capability, in bytes, AuthProxy will read from a presentation. A body
    /// beyond it is refused without being read past the bound, so an unadmitted caller cannot make the
    /// proxy buffer what they send.
    /// </summary>
    public int MaximumLength { get; set; } = 4096;
}
