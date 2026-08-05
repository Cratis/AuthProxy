// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Reflection;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider;

/// <summary>
/// Every page the proxy can ask for must exist in the shipped <c>Pages</c> folder.
/// <para>
/// A missing one is not an error anywhere — <see cref="ErrorPageProvider"/> falls back to a minimal inline
/// document, so the deployment gets a bare "Error 200" heading where the sign-in chooser belongs and
/// nothing reports why. That is exactly how <c>select-provider.html</c> came to be absent while its twin
/// <c>invitation-select-provider.html</c> shipped: both are listed in the documentation as defaults, and
/// only one of them was there.
/// </para>
/// </summary>
public class when_a_well_known_page_has_no_shipped_default : Specification
{
    IEnumerable<string> _pageNames;
    string _pagesDirectory;

    void Establish()
    {
        _pageNames = typeof(WellKnownPageNames)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(_ => _.IsLiteral && _.FieldType == typeof(string))
            .Select(_ => (string)_.GetRawConstantValue()!);

        _pagesDirectory = Path.Combine(AppContext.BaseDirectory, "Pages");
    }

    [Fact] void should_ship_a_default_for_every_well_known_page() =>
        _pageNames.Where(_ => !File.Exists(Path.Combine(_pagesDirectory, _))).ShouldBeEmpty();
}
