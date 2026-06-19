import type { OAuth2Adapter, OAuth2UserInfo } from "adminforth";
import { createRemoteJWKSet, jwtVerify } from "jose";

type ClerkIdTokenClaims = {
  sub?: string;
  email?: string;
  name?: string;
  picture?: string;
};

const HAS_PROTOCOL_RE = /^https?:\/\//;
const CLERK_ID_TOKEN_ALGORITHMS = ["RS256"];

export default class AdminForthAdapterClerkOauth2 implements OAuth2Adapter {
    private clientID: string;
    private clientSecret: string;
    private domain: string;
    private useOpenIdConnect: boolean;
    private clerkJWKS: ReturnType<typeof createRemoteJWKSet>;

    constructor(options: {
      clientID: string;
      clientSecret: string;
      // Clerk Frontend API domain, e.g. "https://your-app.clerk.accounts.dev" or your custom domain
      domain: string;
      useOpenIdConnect?: boolean;
    }) {
      this.clientID = options.clientID;
      this.clientSecret = options.clientSecret;
      // normalize: ensure protocol, strip trailing slash
      let domain = options.domain.trim().replace(/\/+$/, '');
      if (!HAS_PROTOCOL_RE.test(domain)) {
        domain = `https://${domain}`;
      }
      this.domain = domain;
      this.useOpenIdConnect = options.useOpenIdConnect ?? true;
      this.clerkJWKS = createRemoteJWKSet(new URL(`${this.domain}/.well-known/jwks.json`));
    }

    getAuthUrl(): string {
      const params = new URLSearchParams({
        client_id: this.clientID,
        response_type: 'code',
        scope: 'openid email profile',
        prompt: 'login',
      });
      return `${this.domain}/oauth/authorize?${params.toString()}`;
    }

    async getTokenFromCode(code: string, redirect_uri: string): Promise<OAuth2UserInfo> {
      const tokenResponse = await fetch(`${this.domain}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: this.clientID,
          client_secret: this.clientSecret,
          redirect_uri,
          grant_type: 'authorization_code',
        }),
      });

      const tokenData = await tokenResponse.json();

      if (tokenData.error) {
        console.error('Token error:', tokenData);
        throw new Error(tokenData.error_description || tokenData.error);
      }
      if (this.useOpenIdConnect && tokenData.id_token) {
        try {
          const { payload } = await jwtVerify(tokenData.id_token, this.clerkJWKS, {
            issuer: this.domain,
            audience: this.clientID,
            algorithms: CLERK_ID_TOKEN_ALGORITHMS,
          });
          const claims = payload as ClerkIdTokenClaims;

          return {
            provider: this.constructor.name,
            subject: claims.sub,
            email: claims.email,
            fullName: claims.name,
            profilePictureUrl: claims.picture,
          };
        } catch (error) {
          console.error("Error verifying token:", error);
          throw error;
        }
      }

      const userResponse = await fetch(`${this.domain}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      const userData = await userResponse.json();

      if (userData.error) {
        throw new Error(userData.error_description || userData.error);
      }

      return {
        provider: this.constructor.name,
        subject: userData.sub,
        email: userData.email,
        fullName: userData.name,
        profilePictureUrl: userData.picture
      };
    }

    getButtonText(): string {
      return 'Sign in with Clerk';
    }

    getIcon(): string {
      return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path style="fill: currentColor" d="m21.47 20.829-2.881-2.881a.572.572 0 0 0-.7-.084 6.854 6.854 0 0 1-7.081 0 .576.576 0 0 0-.7.084l-2.881 2.881a.576.576 0 0 0-.103.69.57.57 0 0 0 .166.186 12 12 0 0 0 14.113 0 .58.58 0 0 0 .239-.423.576.576 0 0 0-.172-.453Zm.002-17.668-2.88 2.88a.569.569 0 0 1-.701.084A6.857 6.857 0 0 0 8.724 8.08a6.862 6.862 0 0 0-1.222 3.692 6.86 6.86 0 0 0 .978 3.764.573.573 0 0 1-.083.699l-2.881 2.88a.567.567 0 0 1-.864-.063A11.993 11.993 0 0 1 6.771 2.7a11.99 11.99 0 0 1 14.637-.405.566.566 0 0 1 .232.418.57.57 0 0 1-.168.448Zm-7.118 12.261a3.427 3.427 0 1 0 0-6.854 3.427 3.427 0 0 0 0 6.854Z"/></svg>`;
    }
}
