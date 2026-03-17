#!/usr/bin/env node

import express, { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
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

// OAuth 2.0 client credentials endpoint for claude.ai custom integrations
app.post( '/oauth/token', ( req: Request, res: Response ) => {
	const { grant_type, client_id, client_secret } = req.body;
	if ( grant_type !== 'client_credentials' ) {
		res.status( 400 ).json( { error: 'unsupported_grant_type' } );
		return;
	}
	if ( !OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET || !AUTH_TOKEN ) {
		res.status( 500 ).json( { error: 'server_misconfigured' } );
		return;
	}
	if ( client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET ) {
		res.status( 401 ).json( { error: 'invalid_client' } );
		return;
	}
	res.json( { access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 86400 } );
} );

app.use( ( req: Request, res: Response, next: Function ) => {
	if ( req.path === '/health' ) {
		return next();
	}
	if ( !AUTH_TOKEN ) {
		return next();
	}
	const authHeader = req.headers[ 'authorization' ];
	if ( !authHeader || !authHeader.startsWith( 'Bearer ' ) ) {
		res.status( 401 ).json( { error: 'Unauthorized' } );
		return;
	}
	if ( authHeader.slice( 7 ) !== AUTH_TOKEN ) {
		res.status( 401 ).json( { error: 'Unauthorized' } );
		return;
	}
	next();
} );

const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

app.post( '/mcp', async ( req: Request, res: Response ) => {
	const sessionId = req.headers[ 'mcp-session-id' ] as string | undefined;
	let transport: StreamableHTTPServerTransport;

	if ( sessionId && transports[ sessionId ] ) {
		transport = transports[ sessionId ];
	} else if ( !sessionId && isInitializeRequest( req.body ) ) {
		transport = new StreamableHTTPServerTransport( {
			sessionIdGenerator: () => randomUUID(),
			onsessioninitialized: ( sessionId ) => {
				transports[ sessionId ] = transport;
			}
		} );

		transport.onclose = () => {
			if ( transport.sessionId ) {
				delete transports[ transport.sessionId ];
			}
		};
		const server = createServer();

		await server.connect( transport );
	} else {
		res.status( 400 ).json( {
			jsonrpc: '2.0',
			error: {
				code: -32000,
				message: 'Bad Request: No valid session ID provided'
			},
			id: null
		} );
		return;
	}

	await transport.handleRequest( req, res, req.body );
} );

const handleSessionRequest = async ( req: Request, res: Response ): Promise<void> => {
	const sessionId = req.headers[ 'mcp-session-id' ] as string | undefined;
	if ( !sessionId || !transports[ sessionId ] ) {
		res.status( 400 ).send( 'Invalid or missing session ID' );
		return;
	}

	const transport = transports[ sessionId ];
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
