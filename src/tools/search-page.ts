// TODO: Make tools into an interface
import { z } from 'zod';
/* eslint-disable n/no-missing-import */
import type { McpServer, RegisteredTool } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult, TextContent, ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
/* eslint-enable n/no-missing-import */
import { wikiService } from '../common/wikiService.js';
import { makeRestGetRequest } from '../common/utils.js';
import { getMwn } from '../common/mwn.js';
import type { MwRestApiSearchPageResponse, MwRestApiSearchResultObject } from '../types/mwRestApi.js';

export function searchPageTool( server: McpServer ): RegisteredTool {
	// TODO: Not having named parameters is a pain,
	// but using low-level Server type or using a wrapper function are addedd complexity
	return server.tool(
		'search-page',
		'Search wiki page titles and contents for the provided search terms, and returns matching pages.',
		{
			query: z.string().describe( 'Search terms' ),
			limit: z.number().int().min( 1 ).max( 100 ).optional().describe( 'Maximum number of search results to return' )
		},
		{
			title: 'Search page',
			readOnlyHint: true,
			destructiveHint: false
		} as ToolAnnotations,
		async ( { query, limit } ) => handleSearchPageTool( query, limit )
	);
}

async function handleSearchPageTool( query: string, limit?: number ): Promise< CallToolResult > {
	// Try REST API first, fall back to Action API (needed for private wikis
	// or wikis without CirrusSearch)
	let data: MwRestApiSearchPageResponse;
	try {
		data = await makeRestGetRequest<MwRestApiSearchPageResponse>(
			'/v1/search/page',
			{ q: query, ...( limit ? { limit: limit.toString() } : {} ) }
		);
	} catch {
		// REST API failed — fall back to Action API via mwn
		data = { pages: [] };
	}

	const pages = data.pages || [];
	if ( pages.length === 0 ) {
		// Fall back to Action API search (works on all wikis including private ones)
		try {
			return await searchViaActionApi( query, limit );
		} catch ( error ) {
			return {
				content: [
					{ type: 'text', text: `Failed to retrieve search data: ${ ( error as Error ).message }` } as TextContent
				],
				isError: true
			};
		}
	}

	return {
		content: pages.map( getSearchResultToolResult )
	};
}

async function searchViaActionApi( query: string, limit?: number ): Promise< CallToolResult > {
	const mwn = await getMwn();
	const response = await mwn.request( {
		action: 'query',
		list: 'search',
		srsearch: query,
		srlimit: limit || 10,
		srprop: 'snippet|size|wordcount',
		format: 'json'
	} ) as { query: { search: Array<{ title: string; pageid: number; snippet: string; size: number; wordcount: number }> } };

	const results = response.query?.search || [];
	if ( results.length === 0 ) {
		return {
			content: [
				{ type: 'text', text: `No pages found for ${ query }` } as TextContent
			]
		};
	}

	const { server, articlepath } = wikiService.getCurrent().config;
	return {
		content: results.map( ( result ): TextContent => ( {
			type: 'text',
			text: [
				`Title: ${ result.title }`,
				`Description: ${ result.snippet.replace( /<[^>]*>/g, '' ) }`,
				`Page ID: ${ result.pageid }`,
				`Page URL: ${ server }${ articlepath }/${ encodeURIComponent( result.title.replace( / /g, '_' ) ) }`,
				`Size: ${ result.size } bytes, ${ result.wordcount } words`
			].join( '\n' )
		} ) )
	};
}

// TODO: Decide how to handle the tool's result
function getSearchResultToolResult( result: MwRestApiSearchResultObject ): TextContent {
	const { server, articlepath } = wikiService.getCurrent().config;
	return {
		type: 'text',
		text: [
			`Title: ${ result.title }`,
			`Description: ${ result.description ?? 'Not available' }`,
			`Page ID: ${ result.id }`,
			`Page URL: ${ `${ server }${ articlepath }/${ result.key }` }`,
			`Thumbnail URL: ${ result.thumbnail?.url ?? 'Not available' }`
		].join( '\n' )
	};
}
