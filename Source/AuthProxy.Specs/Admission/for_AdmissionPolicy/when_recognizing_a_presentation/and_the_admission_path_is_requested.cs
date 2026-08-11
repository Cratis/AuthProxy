// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.when_recognizing_a_presentation;

/// <summary>
/// The configured path, exactly, is where a capability is presented.
/// </summary>
public class and_the_admission_path_is_requested : given.an_admission_policy
{
    bool _isPresentation;

    void Establish() => _context.Request.Path = "/.cratis/admission";

    void Because() => _isPresentation = _policy.IsPresentation(_context, _config);

    [Fact] void should_recognize_the_presentation() => _isPresentation.ShouldBeTrue();
}
