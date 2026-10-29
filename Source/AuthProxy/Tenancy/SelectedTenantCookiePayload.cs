// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// The content of a signed selected-tenant cookie: the tenant and the account it was selected for.
/// </summary>
/// <param name="TenantId">The selected tenant.</param>
/// <param name="Kind">The kind of account binding.</param>
/// <param name="ProviderKey">The provider key of the account.</param>
/// <param name="Issuer">The issuer of the account.</param>
/// <param name="Subject">The subject of the account.</param>
public sealed record SelectedTenantCookiePayload(string TenantId, string Kind, string ProviderKey, string Issuer, string Subject);
