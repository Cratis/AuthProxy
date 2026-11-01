// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.ApplicationContract.given;

public class missing_key : contract_fixture
{
    protected Exception _error;

    protected async Task Without(string key)
    {
        var source = FromJson();
        var path = $"{ApplicationContractKeys.EnvironmentKey}:{key}";
        var remaining = source.AsEnumerable()
            .Where(_ => !string.Equals(_.Key, path, StringComparison.OrdinalIgnoreCase))
            .ToDictionary(_ => _.Key, _ => _.Value, StringComparer.OrdinalIgnoreCase);
        _error = await Catch.Exception(() =>
        {
            ApplicationContractTranslator.Translate(new ConfigurationBuilder().AddInMemoryCollection(remaining).Build());
            return Task.CompletedTask;
        });
    }
}
