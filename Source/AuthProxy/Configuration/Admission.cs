// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the admission configuration: whether AuthProxy answers anything at all to a caller who has
/// presented nothing, and what it takes to be let in when it does not.
/// </summary>
/// <remarks>
/// This sits beside <see cref="Authorization"/> rather than inside any one flow because it is a different
/// question asked at a different moment. Authorization asks what an authenticated caller may reach;
/// admission asks whether an unauthenticated caller is shown that there is anything here to reach. Leaving
/// the section out — the default — leaves the proxy behaving exactly as it did before this existed.
/// </remarks>
public class Admission
{
    /// <summary>
    /// The configuration section key for the admission settings.
    /// </summary>
    public const string SectionKey = $"{AuthProxy.SectionKey}:Admission";

    /// <summary>
    /// Gets or sets how much of the interactive contract an unadmitted caller may see.
    /// Defaults to <see cref="AdmissionMode.Public"/>, which is what every release before this behaved as.
    /// </summary>
    public AdmissionMode Mode { get; set; } = AdmissionMode.Public;

    /// <summary>
    /// Gets or sets where a capability is presented and who decides whether it admits.
    /// Required while <see cref="Mode"/> is <see cref="AdmissionMode.CapabilityOnly"/>, and ignored
    /// otherwise.
    /// </summary>
    public AdmissionCapability? Capability { get; set; }

    /// <summary>
    /// Gets or sets how long an admitted browser stays admitted. It bounds the whole interactive entry —
    /// choosing a provider, completing the round-trip and coming back — so it is measured in minutes rather
    /// than in the hours a session lasts.
    /// Defaults to ten minutes.
    /// </summary>
    public TimeSpan EntryLifetime { get; set; } = TimeSpan.FromMinutes(10);
}
