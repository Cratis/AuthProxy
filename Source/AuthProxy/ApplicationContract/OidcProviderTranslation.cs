// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Maps an OpenID Connect provider kind onto <see cref="OidcProvider"/>.
/// </summary>
/// <param name="kind">The provider kind.</param>
/// <param name="type">The brand the sign-in page shows.</param>
/// <param name="subjectClaimType">The claim carrying the immutable subject.</param>
/// <param name="requiredKeys">The provider keys that must be present.</param>
/// <param name="authority">Resolves the authority from the provider's values.</param>
public class OidcProviderTranslation(
    ProviderKind kind,
    OidcProviderType type,
    string subjectClaimType,
    IReadOnlyList<string> requiredKeys,
    Func<ProviderValues, string> authority) : IProviderTranslation
{
    /// <inheritdoc/>
    public ProviderKind Kind => kind;

    /// <inheritdoc/>
    public IReadOnlyList<string> RequiredKeys => requiredKeys;

    /// <inheritdoc/>
    public IReadOnlyList<string> OptionalKeys => ["authority", "scopes", "responseMode", "invitationCompletion"];

    /// <inheritdoc/>
    public void Translate(ProviderValues values, ContractSettings settings)
    {
        var path = settings.NextOidcProvider();
        settings.Set($"{path}:Name", values.Identity);
        settings.Set($"{path}:Type", type.ToString());
        settings.Set($"{path}:Authority", authority(values));
        settings.Set($"{path}:ClientId", values.Require("clientId"));
        settings.Set($"{path}:ClientSecret", values.Require("clientSecret"));
        settings.SetList($"{path}:Scopes", values.Scopes());

        var responseMode = values.Find("responseMode");
        if (responseMode is not null)
        {
            if (!Enum.TryParse<OidcResponseMode>(responseMode, ignoreCase: true, out _))
            {
                throw new ApplicationContractException(
                    $"Environment '{values.Environment.Name}': key '{ApplicationContractKeys.ProviderValue(values.Identity, "responseMode")}' must be Query or FormPost.");
            }

            settings.Set($"{path}:ResponseMode", responseMode);
        }

        if (values.InvitationCompletion())
        {
            settings.Set($"{path}:CanonicalIdentity:InvitationCompletionEnabled", "true");
            settings.Set($"{path}:CanonicalIdentity:ProviderKey", values.ProviderKey());
            settings.Set($"{path}:CanonicalIdentity:SubjectClaimType", subjectClaimType);
        }
    }
}
