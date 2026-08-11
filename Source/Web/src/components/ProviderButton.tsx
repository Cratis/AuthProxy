import type { OidcProvider } from '../types';

interface ProviderButtonProps {
    provider: OidcProvider;
    returnUrl: string;
}

export const ProviderButton = ({ provider, returnUrl }: ProviderButtonProps) => {
    const loginUrl = returnUrl
        ? `${provider.loginUrl}?returnUrl=${encodeURIComponent(returnUrl)}`
        : provider.loginUrl;

    return (
        <a href={loginUrl} className="provider-btn">
            Sign in with {provider.name}
        </a>
    );
};
