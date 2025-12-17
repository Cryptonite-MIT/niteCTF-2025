#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <curl/curl.h>

struct MemoryStruct {
    char *memory;
    size_t size;
};

static char* extract_hostname(const char *url) {
    static char hostname[256];

    const char *scheme_end = strstr(url, "://");
    if (!scheme_end) {
        return NULL;
    }

    const char *host_start = scheme_end + 3;

    const char *host_end = host_start;
    while (*host_end && 
           *host_end != ':' && 
           *host_end != '/' && 
           *host_end != '?' && 
           *host_end != '#') {
        host_end++;
    }

    int len = host_end - host_start;
    if (len >= sizeof(hostname)) {
        len = sizeof(hostname) - 1;
    }
    
    strncpy(hostname, host_start, len);
    hostname[len] = '\0';

    for (int i = 0; hostname[i]; i++) {
        hostname[i] = tolower(hostname[i]);
    }
    
    return hostname;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        fprintf(stderr, "Not enough memory\n");
        return 0;
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

int is_blocked_url(const char *url) {
    char *hostname = extract_hostname(url);

    if (hostname && strcmp(hostname, "nite-sso") == 0) {
        return 0; 
    }

    const char *blocked[] = {
        "nite-vault",
        "localhost", "127.", "0.0.0.0", "::1", "[::1]", "0:0:0:0:0:0:0:1",
        "10.", "192.168.", 
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "169.254.",
        "0177.0000.0000.0001", 
        "0x7f.0x0.0x0.0x1",    
        "224.0.0.", "255.255.255.255",
        "::ffff:127.", "::ffff:10.", "::ffff:192.168.", "::ffff:172.",
        "2130706433", "017700000001",
        "localtest.me", "vcap.me", "lvh.me", "127.0.0.1.nip.io",
        "metadata.google.internal", "169.254.169.254",
        NULL
    };

    char url_lower[2048];
    strncpy(url_lower, url, sizeof(url_lower) - 1);
    url_lower[sizeof(url_lower) - 1] = '\0';
    
    for(int i = 0; url_lower[i]; i++) {
        if(url_lower[i] >= 'A' && url_lower[i] <= 'Z') {
            url_lower[i] = url_lower[i] + 32;
        }
    }

    for(int i = 0; blocked[i] != NULL; i++) {
        if(strstr(url_lower, blocked[i]) != NULL) {
            return 1;  
        }
    }

    if(strchr(url_lower, '@') != NULL) {
        return 1;
    }
    
    return 0;  
}

static int redirect_callback(void *clientp, char *primary_ip, char *local_ip, int primary_port, int local_port) {
    CURL *curl = (CURL *)clientp;
    char *effective_url = NULL;
    
    if (curl) {
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);

        if (effective_url && strstr(effective_url, "nite-vault") != NULL){
            return 1;
        }

        if (effective_url) {
            if (strstr(effective_url, "nite-sso") != NULL) {
                return 0; 
            }
        }
    }
    if(is_blocked_url(primary_ip)) {
        return 1; 
    }
    
    return 0; 
}

static int retry_without_redirects(CURL *curl, const char *orig_url, struct MemoryStruct *chunk){

    char *redirect_target = NULL;
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_target);

    if (!redirect_target || strlen(redirect_target) == 0) {
        fprintf(stderr, "No redirect target to retry\n");
        return 1;
    }

    if (chunk->memory) {
        free(chunk->memory);
    }
    chunk->memory = malloc(1);
    if (!chunk->memory) {
        fprintf(stderr, "Not enough memory\n");
        chunk->size = 0;
        return 1;
    }
    chunk->size = 0;

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, NULL); 
    curl_easy_setopt(curl, CURLOPT_URL, redirect_target);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        return 0;  
    }

    fprintf(stderr, "Retry failed: %s\n", curl_easy_strerror(res));
    return 1;
}



void handle_connection_error(CURLcode res, const char *url) {
    fprintf(stderr, "Connection Error: %s\n", curl_easy_strerror(res));
    fprintf(stderr, "Failed to connect to: %s\n", url);
    fprintf(stderr, "Please check the URL and try again\n");
}

void handle_timeout_error(const char *url) {
    fprintf(stderr, "Timeout Error: Request took too long\n");
    fprintf(stderr, "The server at %s did not respond in time\n", url);
    fprintf(stderr, "This could be due to slow network or unresponsive server\n");
}

void handle_ssl_error(CURLcode res, const char *url) {
    fprintf(stderr, "SSL/TLS Error: %s\n", curl_easy_strerror(res));
    fprintf(stderr, "Could not establish secure connection to: %s\n", url);
    fprintf(stderr, "The server's SSL certificate may be invalid or expired\n");
}

void handle_dns_error(const char *url) {
    fprintf(stderr, "DNS Error: Could not resolve hostname\n");
    fprintf(stderr, "Failed to lookup: %s\n", url);
    fprintf(stderr, "Check if the domain name is correct\n");
}

void handle_http_error(long response_code, const char *url) {
    fprintf(stderr, "HTTP Error: Server returned status code %ld\n", response_code);
    
    if(response_code >= 400 && response_code < 500) {
        fprintf(stderr, "Client Error: The request to %s was invalid\n", url);
        
        if(response_code == 401) {
            fprintf(stderr, "Authentication required\n");
        } else if(response_code == 403) {
            fprintf(stderr, "Access forbidden\n");
        } else if(response_code == 404) {
            fprintf(stderr, "Resource not found\n");
        } else if(response_code == 429) {
            fprintf(stderr, "Too many requests - rate limited\n");
        }
    } else if(response_code >= 500) {
        fprintf(stderr, "Server Error: %s is experiencing issues\n", url);
    }
}

void handle_protocol_error(const char *url) {
    fprintf(stderr, "Protocol Error: Unsupported or invalid protocol\n");
    fprintf(stderr, "URL: %s\n", url);
    fprintf(stderr, "Only HTTP and HTTPS protocols are supported\n");
}

int handle_curl_error(CURLcode res, CURL *curl, const char *url, struct MemoryStruct *chunk) {
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    char *effective_url = NULL;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
    
    switch(res) {
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
            handle_dns_error(url);

            fprintf(stderr, "\nTroubleshooting steps:\n");
            fprintf(stderr, "1. Verify the domain name is spelled correctly\n");
            fprintf(stderr, "2. Check your DNS settings\n");
            fprintf(stderr, "3. Try using a different DNS server\n");
            fprintf(stderr, "4. Verify the domain exists using 'nslookup' or 'dig'\n");

            char *scheme_end = strstr(url, "://");
            if(scheme_end) {
                char *host_start = scheme_end + 3;
                char *host_end = strchr(host_start, '/');
                char hostname[256] = {0};
                
                if(host_end) {
                    int len = host_end - host_start;
                    if(len < 256) {
                        strncpy(hostname, host_start, len);
                        fprintf(stderr, "Failed to resolve hostname: %s\n", hostname);
                    }
                } else {
                    strncpy(hostname, host_start, 255);
                    fprintf(stderr, "Failed to resolve hostname: %s\n", hostname);
                }
            }
            return 1;
            
        case CURLE_COULDNT_CONNECT:
        case CURLE_OPERATION_TIMEDOUT:
            if(res == CURLE_OPERATION_TIMEDOUT) {
                handle_timeout_error(url);

                fprintf(stderr, "\nTimeout details:\n");
                fprintf(stderr, "- Connection timeout: 5 seconds\n");
                fprintf(stderr, "- Total timeout: 10 seconds\n");
                fprintf(stderr, "\nPossible causes:\n");
                fprintf(stderr, "1. Server is overloaded or slow to respond\n");
                fprintf(stderr, "2. Network congestion or packet loss\n");
                fprintf(stderr, "3. Firewall blocking the connection\n");
                fprintf(stderr, "4. Server is down or unreachable\n");

                long response_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                if(response_code > 0) {
                    fprintf(stderr, "Partial response received (HTTP %ld) before timeout\n", response_code);
                }
            } else {
                handle_connection_error(res, url);

                fprintf(stderr, "\nConnection diagnostics:\n");

                double namelookup_time = 0, connect_time = 0;
                curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &namelookup_time);
                curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &connect_time);
                
                fprintf(stderr, "DNS lookup time: %.3f seconds\n", namelookup_time);
                fprintf(stderr, "Connection attempt time: %.3f seconds\n", connect_time);
                
                fprintf(stderr, "\nPossible reasons:\n");
                fprintf(stderr, "1. Server is not listening on the specified port\n");
                fprintf(stderr, "2. Firewall or network policy blocking access\n");
                fprintf(stderr, "3. Server actively refused the connection\n");
                fprintf(stderr, "4. Network routing issues\n");
            }
            return 1;
            
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case CURLE_SSL_CACERT:
        case CURLE_SSL_CACERT_BADFILE:
        case CURLE_SSL_SHUTDOWN_FAILED:
        case CURLE_SSL_CRL_BADFILE:
        case CURLE_SSL_ISSUER_ERROR:
            handle_ssl_error(res, url);

            fprintf(stderr, "\nSSL/TLS Diagnostics:\n");

            long ssl_verify_result = 0;
            curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &ssl_verify_result);
            fprintf(stderr, "SSL verification result code: %ld\n", ssl_verify_result);

            if(res == CURLE_SSL_CACERT) {
                fprintf(stderr, "\nCertificate Authority (CA) Error:\n");
                fprintf(stderr, "- The server's certificate is not signed by a trusted CA\n");
                fprintf(stderr, "- The certificate chain is incomplete\n");
                fprintf(stderr, "- Your system's CA bundle may be outdated\n");
            } else if(res == CURLE_SSL_CERTPROBLEM) {
                fprintf(stderr, "\nCertificate Problem:\n");
                fprintf(stderr, "- The certificate may be expired or not yet valid\n");
                fprintf(stderr, "- Certificate hostname doesn't match the URL\n");
                fprintf(stderr, "- Certificate has been revoked\n");
            } else if(res == CURLE_SSL_CIPHER) {
                fprintf(stderr, "\nCipher Suite Mismatch:\n");
                fprintf(stderr, "- No common encryption algorithm between client and server\n");
                fprintf(stderr, "- Server may only support weak/deprecated ciphers\n");
            }
            
            fprintf(stderr, "\nFor testing purposes only (NOT production):\n");
            fprintf(stderr, "You could disable SSL verification, but this is insecure\n");
            
            return 1;
            
        case CURLE_UNSUPPORTED_PROTOCOL:
            handle_protocol_error(url);

            char protocol[32] = {0};
            char *proto_end = strstr(url, "://");
            if(proto_end) {
                int proto_len = proto_end - url;
                if(proto_len < 32) {
                    strncpy(protocol, url, proto_len);
                    fprintf(stderr, "Attempted protocol: %s\n", protocol);
                }
            }
            
            fprintf(stderr, "\nSupported protocols:\n");
            fprintf(stderr, "- HTTP  (http://)\n");
            fprintf(stderr, "- HTTPS (https://)\n");
            fprintf(stderr, "\nBlocked protocols for security:\n");
            fprintf(stderr, "- FILE  (file://)\n");
            fprintf(stderr, "- FTP   (ftp://)\n");
            fprintf(stderr, "- DICT  (dict://)\n");
            fprintf(stderr, "- GOPHER (gopher://)\n");
            fprintf(stderr, "- LDAP  (ldap://)\n");
            
            return 1;
            
        case CURLE_URL_MALFORMAT:
            fprintf(stderr, "Malformed URL: %s\n", url);
            fprintf(stderr, "Please check the URL format\n");

            fprintf(stderr, "\nValid URL format:\n");
            fprintf(stderr, "protocol://hostname[:port][/path][?query][#fragment]\n");
            fprintf(stderr, "\nExamples:\n");
            fprintf(stderr, "- https://example.com\n");
            fprintf(stderr, "- https://example.com:8080/path\n");
            fprintf(stderr, "- http://example.com/api?key=value\n");

            if(strstr(url, "://") == NULL) {
                fprintf(stderr, "\nIssue detected: Missing protocol (http:// or https://)\n");
            } else if(strstr(url, " ") != NULL) {
                fprintf(stderr, "\nIssue detected: URL contains spaces\n");
            }
            
            return 1;

        case CURLE_TOO_MANY_REDIRECTS:
            fprintf(stderr, "Redirect Error: Too many redirects encountered\n");

            char *redirect_url = NULL;
            curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
            
            if(redirect_url && strlen(redirect_url) > 0) {

                free(chunk->memory);
                chunk->memory = malloc(1);
                chunk->size = 0;
                
                curl_easy_setopt(curl, CURLOPT_URL, redirect_url);
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
                curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, NULL);               
                CURLcode res2 = curl_easy_perform(curl);               
                if(res2 == CURLE_OK && chunk->size > 0) {
                    return 0; 
                }
            }
            return 1;
            
        case CURLE_GOT_NOTHING:
            fprintf(stderr, "Empty Response: Server returned no data\n");
            fprintf(stderr, "The server closed the connection without sending data\n");

            double connect_time = 0;
            curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &connect_time);
            
            if(connect_time > 0) {
                fprintf(stderr, "Connection was established (%.3f seconds)\n", connect_time);
                fprintf(stderr, "But server sent no HTTP response\n");
                
                fprintf(stderr, "\nPossible causes:\n");
                fprintf(stderr, "1. Server process crashed after accepting connection\n");
                fprintf(stderr, "2. Wrong port - connected to non-HTTP service\n");
                fprintf(stderr, "3. Server requires specific headers or authentication\n");
                fprintf(stderr, "4. Protocol mismatch (trying HTTP on HTTPS port or vice versa)\n");
            }
            
            return 1;
            
        case CURLE_RECV_ERROR:
        case CURLE_SEND_ERROR:
            fprintf(stderr, "Network Error: Failed to send/receive data\n");
            fprintf(stderr, "Connection to %s was interrupted\n", url);

            double total_time = 0, starttransfer_time = 0;
            curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
            curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &starttransfer_time);
            
            fprintf(stderr, "\nTransfer statistics:\n");
            fprintf(stderr, "Time to first byte: %.3f seconds\n", starttransfer_time);
            fprintf(stderr, "Total time before failure: %.3f seconds\n", total_time);
            
            if(res == CURLE_RECV_ERROR) {
                fprintf(stderr, "\nReceive error details:\n");
                fprintf(stderr, "- Network connection dropped while receiving data\n");
                fprintf(stderr, "- Server may have crashed or been restarted\n");
                fprintf(stderr, "- Network equipment may have reset the connection\n");
            } else {
                fprintf(stderr, "\nSend error details:\n");
                fprintf(stderr, "- Failed to send request to server\n");
                fprintf(stderr, "- Connection may have been closed by remote host\n");
                fprintf(stderr, "- Network interface may be down\n");
            }
            
            return 1;
            
        case CURLE_ABORTED_BY_CALLBACK:
            fprintf(stderr, "Request Aborted: Blocked by security policy\n");

            char *attempted_url = NULL;
            curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &attempted_url);
            
            if(attempted_url && is_blocked_url(attempted_url)) {
                fprintf(stderr, "Blocked URL: %s\n", attempted_url);
                fprintf(stderr, "\nSecurity policy violation detected:\n");
                fprintf(stderr, "The request attempted to access a restricted resource\n");
                fprintf(stderr, "This may be a redirect to an internal address\n");

                long redirect_count = 0;
                curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirect_count);
                
                if(redirect_count > 0) {
                    fprintf(stderr, "\nRedirects followed before block: %ld\n", redirect_count);
                    fprintf(stderr, "The final redirect target violated security policy\n");
                }
            }
            
            fprintf(stderr, "\nBlocked resource types:\n");
            fprintf(stderr, "- Internal/private IP addresses\n");
            fprintf(stderr, "- Localhost and loopback addresses\n");
            fprintf(stderr, "- Cloud metadata endpoints\n");
            fprintf(stderr, "- Private network ranges (10.x, 192.168.x, 172.16-31.x)\n");
            
            return 1;
            
        case CURLE_HTTP_RETURNED_ERROR:
            handle_http_error(response_code, url);

            fprintf(stderr, "\nHTTP Status Code Details:\n");
            
            if(response_code == 400) {
                fprintf(stderr, "Bad Request - The server couldn't understand the request\n");
                fprintf(stderr, "This usually means malformed syntax or invalid parameters\n");
            } else if(response_code == 401) {
                fprintf(stderr, "Unauthorized - Authentication is required\n");
                fprintf(stderr, "You need to provide valid credentials (API key, token, etc.)\n");
            } else if(response_code == 403) {
                fprintf(stderr, "Forbidden - You don't have permission to access this resource\n");
                fprintf(stderr, "Authentication was successful but access is still denied\n");
            } else if(response_code == 404) {
                fprintf(stderr, "Not Found - The requested resource doesn't exist\n");
                fprintf(stderr, "Check the URL path and ensure the resource exists\n");
            } else if(response_code == 405) {
                fprintf(stderr, "Method Not Allowed - HTTP method not supported for this resource\n");
            } else if(response_code == 429) {
                fprintf(stderr, "Too Many Requests - Rate limit exceeded\n");
                fprintf(stderr, "You've made too many requests in a short time period\n");
                fprintf(stderr, "Wait a while before making more requests\n");
            } else if(response_code == 500) {
                fprintf(stderr, "Internal Server Error - The server encountered an error\n");
                fprintf(stderr, "This is a problem with the server, not your request\n");
            } else if(response_code == 502) {
                fprintf(stderr, "Bad Gateway - Server received invalid response from upstream\n");
            } else if(response_code == 503) {
                fprintf(stderr, "Service Unavailable - Server temporarily can't handle the request\n");
                fprintf(stderr, "The service may be down for maintenance or overloaded\n");
            } else if(response_code == 504) {
                fprintf(stderr, "Gateway Timeout - Upstream server didn't respond in time\n");
            }
            
            return 1;
            
        default:
            fprintf(stderr, "Unknown Error: %s\n", curl_easy_strerror(res));
            fprintf(stderr, "An unexpected error occurred\n");
            return 1;
    }
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <url>\n", argv[0]);
        fprintf(stderr, "Example: %s https://example.com\n", argv[0]);
        return 1;
    }
    
    const char *url = argv[1];
    
    if(strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        fprintf(stderr, "Error: URL must start with http:// or https://\n");
        return 1;
    }
    
    if(is_blocked_url(url)) {
        fprintf(stderr, "ERROR: Access to internal/private addresses is not allowed\n");
        return 2;
    }
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    if(!chunk.memory) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(!curl) {
        fprintf(stderr, "Failed to initialize CURL\n");
        free(chunk.memory);
        curl_global_cleanup();
        return 1;
    }
    

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "nite-Fetcher/1.0");
    curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, redirect_callback);
    curl_easy_setopt(curl, CURLOPT_PREREQDATA, curl);
    
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
    curl_easy_setopt(curl, CURLOPT_NETRC_FILE, "/root/.netrc");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

    res = curl_easy_perform(curl);
    
    long redirect_count = 0;
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirect_count);
    
    char *effective_url = NULL;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
    
    double total_time = 0;
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
    
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    if(res != CURLE_OK) {
        int error_handled = handle_curl_error(res, curl, url, &chunk);
        
        curl_easy_cleanup(curl);
        
        if(error_handled == 0 && chunk.size > 0) {
            printf("%s", chunk.memory);
            free(chunk.memory);
            curl_global_cleanup();
            return 0;
        }
        
        free(chunk.memory);
        curl_global_cleanup();
        return 3;
    }
    
    if(response_code >= 400) {
        handle_http_error(response_code, url);
    }
    
    if(chunk.size > 0) {
        printf("%s", chunk.memory);
    } else {
        fprintf(stderr, "Warning: Server returned empty response\n");
    }
    
    curl_easy_cleanup(curl);
    free(chunk.memory);
    curl_global_cleanup();
    
    return 0;
}
