// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents how much of the interactive contract a caller who has presented nothing may see.
/// </summary>
/// <remarks>
/// AuthProxy's interactive surface — the provider list, the per-provider challenge endpoints, the
/// provider-selection page and every page asset behind it — is public by design, because a person who has
/// never signed in has to be able to reach it in order to sign in at all. That design is right for a
/// deployment whose front door is meant to be found, and wrong for one whose existence is not meant to be
/// discoverable at all.
/// <para>
/// The mode is the switch between those two deployments, and nothing else in the proxy changes with it.
/// </para>
/// </remarks>
public enum AdmissionMode
{
    /// <summary>
    /// The interactive contract is public: everything AuthProxy has always answered to a caller with no
    /// session, it still answers. This is the default and the behavior of every release before the mode
    /// existed.
    /// </summary>
    Public = 0,

    /// <summary>
    /// Nothing at all is answered until a caller presents a capability the deployment's own verifier
    /// admits. Every request that has not been admitted receives one indistinguishable refusal, so the
    /// deployment discloses neither which paths exist, nor which providers are configured, nor whether a
    /// given capability was ever valid.
    /// </summary>
    /// <remarks>
    /// This is an opt-in posture, not a hardening of the default: turning it on closes a contract that
    /// other deployments depend on being open.
    /// </remarks>
    CapabilityOnly = 1
}
