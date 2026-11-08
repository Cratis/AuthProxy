import type { OidcProvider } from '../types';

interface ProviderButtonProps {
    provider: OidcProvider;
    returnUrl: string;
    fresh?: boolean;
    maxAge?: string;
}

export const ProviderButton = ({ provider, returnUrl, fresh, maxAge = '300' }: ProviderButtonProps) => {
    let loginUrl = returnUrl
        ? `${provider.loginUrl}?returnUrl=${encodeURIComponent(returnUrl)}`
        : provider.loginUrl;
    if (fresh) {
        loginUrl += `${returnUrl ? '&' : '?'}fresh=1&maxAge=${encodeURIComponent(maxAge)}`;
    }

    return (
        <a href={loginUrl} className="provider-btn">
            Sign in with {provider.name}
        </a>
    );
};
