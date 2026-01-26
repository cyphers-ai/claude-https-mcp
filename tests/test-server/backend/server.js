/**
 * claude-https Test Backend Server
 *
 * Echo server that returns request details for verification.
 * Supports various test scenarios via control headers.
 */

const http = require('http');
const url = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SERVER_NAME = 'claude-https-test-backend';
const SERVER_VERSION = '1.0.0';

/**
 * Generate a unique request ID
 */
function generateRequestId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(4).toString('hex');
    return `${timestamp}-${random}`;
}

/**
 * Try to parse JSON, return original string if fails
 */
function tryParseJson(str) {
    if (!str || str.trim() === '') return null;
    try {
        return JSON.parse(str);
    } catch {
        return str;
    }
}

/**
 * Get content type from request
 */
function getContentType(headers) {
    const ct = headers['content-type'] || '';
    return ct.split(';')[0].trim();
}

/**
 * Create the HTTP server
 */
const server = http.createServer((req, res) => {
    const requestId = generateRequestId();
    const startTime = Date.now();
    const parsedUrl = url.parse(req.url, true);

    // Health check endpoint (fast path)
    if (parsedUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
        return;
    }

    // Collect request body
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));

    req.on('end', () => {
        const bodyBuffer = Buffer.concat(chunks);
        const bodyString = bodyBuffer.toString('utf8');

        // Read test control headers
        const delayMs = parseInt(req.headers['x-delay-ms'] || '0', 10);
        const responseSize = parseInt(req.headers['x-response-size'] || '0', 10);
        const statusCode = parseInt(req.headers['x-status-code'] || '200', 10);
        const errorType = req.headers['x-error-type'];
        const customHeaders = req.headers['x-custom-response-headers'];

        // Simulate error scenarios
        if (errorType === 'connection-reset') {
            req.socket.destroy();
            return;
        }

        if (errorType === 'timeout' || errorType === 'hang') {
            // Never respond - let it timeout
            return;
        }

        if (errorType === 'slow-headers') {
            // Delay before sending headers
            setTimeout(() => {
                res.writeHead(200);
                res.end('Slow headers response');
            }, 60000); // 60 seconds
            return;
        }

        // Build response object
        const response = {
            meta: {
                requestId,
                timestamp: new Date().toISOString(),
                processingTime: null, // Will be set before sending
                server: {
                    name: SERVER_NAME,
                    version: SERVER_VERSION,
                },
            },
            request: {
                method: req.method,
                url: req.url,
                path: parsedUrl.pathname,
                query: parsedUrl.query,
                headers: { ...req.headers },
                body: tryParseJson(bodyString),
                bodyRaw: bodyString.length > 0 ? bodyString : null,
                contentType: getContentType(req.headers),
                contentLength: bodyBuffer.length,
            },
            connection: {
                remoteAddress: req.socket.remoteAddress,
                remotePort: req.socket.remotePort,
                localAddress: req.socket.localAddress,
                localPort: req.socket.localPort,
                httpVersion: req.httpVersion,
            },
            tls: {
                // These headers are set by nginx
                protocol: req.headers['x-tls-version'] || req.headers['x-ssl-protocol'] || null,
                cipher: req.headers['x-tls-cipher'] || req.headers['x-ssl-cipher'] || null,
                clientCertSubject: req.headers['x-client-cert-subject'] || null,
                clientCertVerify: req.headers['x-client-cert-verify'] || null,
                clientCertSerial: req.headers['x-client-cert-serial'] || null,
            },
            test: {
                // Echo back any test parameters
                delayMs: delayMs > 0 ? delayMs : null,
                responseSize: responseSize > 0 ? responseSize : null,
                statusCode: statusCode !== 200 ? statusCode : null,
            },
        };

        // Add padding for large response tests
        if (responseSize > 0) {
            response.padding = 'x'.repeat(Math.min(responseSize, 10 * 1024 * 1024)); // Max 10MB
        }

        // Prepare response headers
        const responseHeaders = {
            'Content-Type': 'application/json',
            'X-Request-Id': requestId,
            'X-Server': SERVER_NAME,
            'X-Processing-Time': null, // Will be set before sending
        };

        // Parse custom headers if provided
        if (customHeaders) {
            try {
                const custom = JSON.parse(customHeaders);
                Object.assign(responseHeaders, custom);
            } catch {
                // Ignore invalid JSON
            }
        }

        // Send response (with optional delay)
        const sendResponse = () => {
            const processingTime = Date.now() - startTime;
            response.meta.processingTime = `${processingTime}ms`;
            responseHeaders['X-Processing-Time'] = `${processingTime}ms`;

            res.writeHead(statusCode, responseHeaders);
            res.end(JSON.stringify(response, null, 2));
        };

        if (delayMs > 0) {
            setTimeout(sendResponse, Math.min(delayMs, 300000)); // Max 5 min delay
        } else {
            sendResponse();
        }
    });

    req.on('error', (err) => {
        console.error(`Request error: ${err.message}`);
    });
});

// Error handling
server.on('error', (err) => {
    console.error(`Server error: ${err.message}`);
    process.exit(1);
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`${SERVER_NAME} v${SERVER_VERSION}`);
    console.log(`Listening on port ${PORT}`);
    console.log('');
    console.log('Control Headers:');
    console.log('  X-Delay-Ms: <ms>           Delay response by N milliseconds');
    console.log('  X-Response-Size: <bytes>   Add padding to response');
    console.log('  X-Status-Code: <code>      Return custom status code');
    console.log('  X-Error-Type: <type>       Simulate errors (connection-reset, timeout, hang)');
    console.log('');
});

// Graceful shutdown
const shutdown = () => {
    console.log('Shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });

    // Force close after 10 seconds
    setTimeout(() => {
        console.error('Forced shutdown');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
