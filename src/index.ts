#!/usr/bin/env node
/**
 * Claude HTTPS MCP Server
 *
 * An MCP server that provides a secure HTTPS fetch tool with custom TLS configuration.
 * Configuration is loaded from ~/.claude/https-config.json
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ErrorCode,
} from '@modelcontextprotocol/sdk/types.js';
import { loadAndValidateConfig, getConfigPath, DEFAULT_CONFIG } from './config/loader.js';
import { makeRequest } from './http/client.js';
import type { HttpsConfig, HttpsRequestOptions } from './config/types.js';
import { getLicenseInfo } from './license/license.js';

// Load configuration
let config: HttpsConfig;
try {
  config = loadAndValidateConfig();
} catch (error) {
  // If config loading fails, use defaults but log the error
  console.error(`Warning: Failed to load config, using defaults: ${error}`);
  config = DEFAULT_CONFIG;
}

// Create MCP server
const server = new Server(
  {
    name: 'claude-https',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const licenseInfo = getLicenseInfo(config.license.key);

  return {
    tools: [
      {
        name: 'SecureWebFetch',
        description: `Fetch content from an HTTPS URL with custom TLS configuration.

Configuration loaded from: ${getConfigPath()}
License: ${licenseInfo.hasLicense ? `Pro (${licenseInfo.customer})` : 'Free tier'}
${licenseInfo.hasLicense ? `Features: ${licenseInfo.features.join(', ')}` : ''}

TLS Settings:
- Version: ${config.tls.minVersion} - ${config.tls.maxVersion}
- Cipher Profile: ${config.tls.cipherProfile}
- CA Mode: ${config.ca.mode}
- Certificate Validation: ${config.tls.rejectUnauthorized ? 'Enabled' : 'Disabled'}

Pro Features:
- mTLS: ${config.clientCert.enabled ? 'Enabled' : 'Disabled'}
- Pinning: ${config.pinning.enabled ? 'Enabled' : 'Disabled'}
- Revocation: ${config.revocation.enabled ? 'Enabled' : 'Disabled'}`,
        inputSchema: {
          type: 'object',
          properties: {
            url: {
              type: 'string',
              description: 'The HTTPS URL to fetch',
            },
            method: {
              type: 'string',
              enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
              description: 'HTTP method (default: GET)',
              default: 'GET',
            },
            headers: {
              type: 'object',
              additionalProperties: {
                type: 'string',
              },
              description: 'Request headers',
            },
            body: {
              type: 'string',
              description: 'Request body for POST/PUT/PATCH requests',
            },
            timeout: {
              type: 'number',
              description: `Request timeout in milliseconds (default: ${config.defaults.timeoutMs})`,
            },
          },
          required: ['url'],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== 'SecureWebFetch') {
    throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
  }

  const args = request.params.arguments as {
    url?: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
  };

  // Validate URL
  if (!args.url) {
    throw new McpError(ErrorCode.InvalidParams, 'URL is required');
  }

  // Validate URL is HTTPS
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(args.url);
    if (parsedUrl.protocol !== 'https:') {
      throw new McpError(ErrorCode.InvalidParams, 'Only HTTPS URLs are supported');
    }
  } catch (error) {
    if (error instanceof McpError) throw error;
    throw new McpError(ErrorCode.InvalidParams, `Invalid URL: ${args.url}`);
  }

  // Build request options
  const requestOptions: HttpsRequestOptions = {
    method: (args.method as HttpsRequestOptions['method']) || 'GET',
    url: args.url,
    headers: args.headers,
    body: args.body,
    timeout: args.timeout,
  };

  try {
    const response = await makeRequest(requestOptions, config);

    // Format response for MCP
    const responseText = [
      `HTTP ${response.statusCode} ${response.statusMessage}`,
      '',
      '--- Headers ---',
      ...Object.entries(response.headers)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`),
      '',
      '--- Body ---',
      response.body,
    ].join('\n');

    return {
      content: [
        {
          type: 'text',
          text: responseText,
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    return {
      content: [
        {
          type: 'text',
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Claude HTTPS MCP server started');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});
