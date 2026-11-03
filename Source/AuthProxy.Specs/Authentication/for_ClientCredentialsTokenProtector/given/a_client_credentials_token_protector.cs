// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.given;

public class a_client_credentials_token_protector : Specification
{
    protected ManualTime Time;
    protected IDataProtectionProvider DataProtection;
    protected ClientCredentialsTokenProtector Protector;
    protected ConfiguredClientCredentialsService Service;

    protected virtual TimeSpan FamilyLifetime => TimeSpan.FromDays(30);

    void Establish()
    {
        // Anchored at the real current time: access tokens are still checked against the wall clock.
        Time = new ManualTime(DateTimeOffset.UtcNow);
        DataProtection = new EphemeralDataProtectionProvider();
        Protector = new ClientCredentialsTokenProtector(DataProtection, Time);
        Service = new ConfiguredClientCredentialsService("portal", "/api", new Uri("http://portal.test/verify"))
        {
            RefreshTokenFamilyLifetime = FamilyLifetime,
        };
    }
}
