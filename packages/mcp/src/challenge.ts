/** A refusal with its HTTP status, `WWW-Authenticate` value and JSON body. */
export class LumoAuthChallenge extends Error {
    constructor(
        public readonly status: number,
        public readonly wwwAuthenticate: string | undefined,
        public readonly body: { error: string; error_description?: string },
    ) {
        super(body.error_description ?? body.error);
        this.name = 'LumoAuthChallenge';
    }
}

/** A small HTTP answer that the Node and fetch adapters render. */
export interface SimpleResponse {
    status: number;
    headers: Record<string, string>;
    body?: string;
}
