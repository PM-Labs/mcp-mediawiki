#!/usr/bin/env node

import express, { Request, Response } from 'express';
import { createHash, randomUUID } from 'node:crypto';
/* eslint-disable n/no-missing-import */
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
/* eslint-enable n/no-missing-import */
import { createServer } from './server.js';

const app = express();
app.use( express.json() );
app.use( express.urlencoded( { extended: false } ) );

const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN?.trim();
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID?.trim();
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET?.trim();

// In-memory store for PKCE authorization codes (expires in 5 minutes)
interface AuthCode {
	codeChallenge: string;
	codeChallengeMethod: string;
	redirectUri: string;
	expiresAt: number;
}
const authCodes: Record<string, AuthCode> = {};

// OAuth protected resource metadata (RFC 8707)
app.get( '/.well-known/oauth-protected-resource', ( req: Request, res: Response ) => {
	const base = `https://${ req.headers.host }`;
	res.json( {
		resource: `${ base }/mcp`,
		authorization_servers: [ base ]
	} );
} );

// OAuth authorization server metadata (RFC 8414)
app.get( '/.well-known/oauth-authorization-server', ( req: Request, res: Response ) => {
	const base = `https://${ req.headers.host }`;
	res.json( {
		issuer: base,
		authorization_endpoint: `${ base }/authorize`,
		token_endpoint: `${ base }/oauth/token`,
		grant_types_supported: [ 'authorization_code', 'client_credentials' ],
		code_challenge_methods_supported: [ 'S256' ],
		response_types_supported: [ 'code' ]
	} );
} );

// OAuth 2.0 authorization endpoint — validates client, issues code, redirects back
app.get( '/authorize', ( req: Request, res: Response ) => {
	const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query as Record<string, string>;

	if ( client_id !== OAUTH_CLIENT_ID ) {
		res.status( 401 ).json( { error: 'invalid_client' } );
		return;
	}
	if ( response_type !== 'code' ) {
		res.status( 400 ).json( { error: 'unsupported_response_type' } );
		return;
	}
	if ( !code_challenge ) {
		res.status( 400 ).json( { error: 'code_challenge required' } );
		return;
	}

	const code = randomUUID();
	authCodes[ code ] = {
		codeChallenge: code_challenge,
		codeChallengeMethod: code_challenge_method || 'S256',
		redirectUri: redirect_uri,
		expiresAt: Date.now() + 5 * 60 * 1000
	};

	const redirectUrl = new URL( redirect_uri );
	redirectUrl.searchParams.set( 'code', code );
	if ( state ) {
		redirectUrl.searchParams.set( 'state', state );
	}

	res.redirect( redirectUrl.toString() );
} );

// OAuth 2.0 token endpoint — supports authorization_code (PKCE) and client_credentials
app.post( '/oauth/token', ( req: Request, res: Response ) => {
	if ( !OAUTH_CLIENT_ID || !AUTH_TOKEN ) {
		res.status( 500 ).json( { error: 'server_misconfigured' } );
		return;
	}

	const grant_type = req.body.grant_type;

	if ( grant_type === 'authorization_code' ) {
		const { code, code_verifier, redirect_uri } = req.body;

		const stored = authCodes[ code ];
		if ( !stored || stored.expiresAt < Date.now() ) {
			res.status( 400 ).json( { error: 'invalid_grant' } );
			return;
		}

		// Validate PKCE: base64url(sha256(code_verifier)) must equal code_challenge
		const expected = createHash( 'sha256' ).update( code_verifier ).digest( 'base64url' );
		if ( expected !== stored.codeChallenge ) {
			res.status( 400 ).json( { error: 'invalid_grant' } );
			return;
		}

		if ( redirect_uri && redirect_uri !== stored.redirectUri ) {
			res.status( 400 ).json( { error: 'invalid_grant' } );
			return;
		}

		delete authCodes[ code ];
		res.json( { access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 2592000 } );
		return;
	}

	if ( grant_type === 'client_credentials' || !grant_type ) {
		if ( !OAUTH_CLIENT_SECRET ) {
			res.status( 500 ).json( { error: 'server_misconfigured' } );
			return;
		}

		let client_id: string | undefined;
		let client_secret: string | undefined;
		const basicAuth = req.headers[ 'authorization' ];
		if ( basicAuth && basicAuth.startsWith( 'Basic ' ) ) {
			const decoded = Buffer.from( basicAuth.slice( 6 ), 'base64' ).toString();
			const colon = decoded.indexOf( ':' );
			client_id = decoded.slice( 0, colon );
			client_secret = decoded.slice( colon + 1 );
		} else {
			client_id = req.body.client_id;
			client_secret = req.body.client_secret;
		}

		if ( client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET ) {
			res.status( 401 ).json( { error: 'invalid_client' } );
			return;
		}
		res.json( { access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 2592000 } );
		return;
	}

	res.status( 400 ).json( { error: 'unsupported_grant_type' } );
} );

// Bearer token auth middleware — protects /mcp, exempts OAuth and health endpoints
app.use( ( req: Request, res: Response, next: Function ) => {
	if ( req.path === '/health' || req.path.startsWith( '/.well-known/' ) ||
		req.path === '/authorize' || req.path === '/oauth/token' ) {
		return next();
	}
	if ( !AUTH_TOKEN ) {
		return next();
	}
	const authHeader = req.headers[ 'authorization' ];
	if ( !authHeader || !authHeader.startsWith( 'Bearer ' ) ) {
		res.status( 401 )
			.set( 'WWW-Authenticate', `Bearer resource_metadata="https://${ req.headers.host }/.well-known/oauth-protected-resource"` )
			.json( { error: 'Unauthorized' } );
		return;
	}
	if ( authHeader.slice( 7 ) !== AUTH_TOKEN ) {
		res.status( 401 )
			.set( 'WWW-Authenticate', `Bearer error="invalid_token"` )
			.json( { error: 'Unauthorized' } );
		return;
	}
	next();
} );

const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};
app.post( '/mcp', async ( req: Request, res: Response ) => {
	const sessionId = req.headers[ 'mcp-session-id' ] as string | undefined;

	// Known active session — reuse its transport.
	if ( sessionId && transports[ sessionId ] ) {
		await transports[ sessionId ].handleRequest( req, res, req.body );
		return;
	}

	// No session id + initialize request — create a new session.
	if ( !sessionId && isInitializeRequest( req.body ) ) {
		const transport = new StreamableHTTPServerTransport( {
			sessionIdGenerator: () => randomUUID(),
			onsessioninitialized: ( newId: string ) => {
				transports[ newId ] = transport;
			}
		} );
		transport.onclose = () => {
			if ( transport.sessionId ) delete transports[ transport.sessionId ];
		};
		const server = createServer();
		await server.connect( transport );
		await transport.handleRequest( req, res, req.body );
		return;
	}

	// Unknown session id — return 404 per MCP spec. A well-behaved client
	// will reinitialize cleanly. Do NOT silently resurrect — see
	// PM-Labs/mcp-playwright@1d75780 for root-cause analysis.
	if ( sessionId ) {
		res.status( 404 ).json( {
			jsonrpc: '2.0',
			error: { code: -32001, message: 'Session not found' },
			id: null
		} );
		return;
	}

	// No session id and not an initialize — malformed request.
	res.status( 400 ).json( {
		jsonrpc: '2.0',
		error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
		id: null
	} );
} );

const handleSessionRequest = async ( req: Request, res: Response ): Promise<void> => {
	const sessionId = req.headers[ 'mcp-session-id' ] as string | undefined;
	if ( !sessionId ) {
		res.status( 400 ).send( 'Missing session ID' );
		return;
	}
	const transport = transports[ sessionId ];
	if ( !transport ) {
		res.status( 404 ).json( {
			jsonrpc: '2.0',
			error: { code: -32001, message: 'Session not found' },
			id: null
		} );
		return;
	}
	await transport.handleRequest( req, res );
};

app.get( '/mcp', handleSessionRequest );

app.delete( '/mcp', handleSessionRequest );

// Used for the health check in the container
app.get( '/health', ( _req: Request, res: Response ) => {
	res.status( 200 ).json( { status: 'ok' } );
} );

const PORT = process.env.PORT || 3000;
app.listen( PORT, () => {
	console.error( `MCP Streamable HTTP Server listening on port ${ PORT }` );
} );
