/* Desmond Preston 2015

Compile with: sudo g++ -std=c++11 oauth.cpp SHA1.cpp HMAC_SHA1.cpp main.cpp -lcrypto -lcurl

Oauth implementation

Create request in 2 steps:
1. Create new ConnectionConfig and assign values to Consumerkey, ConsumerSecret, hostname, request_token_url, oauth_ver, oauth_callback, auth_token
2. Create new Oauth object with parameters:
    Connection (ConnectionConfig); this is the ConnectionConfig object you created in step 1 or another connection config already created.
    httpMethod (string); the method to use for http request (GET, POST).
    url (string); url to make request to.
*/

#ifndef OAUTH
#define OAUTH
#endif

#include <iostream>
#include <fstream>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "HMAC_SHA1.h"
#include <map>
#include <curl/curl.h>

using namespace std;

typedef map<string, string> OAuthParameters;

/* Contains all info relevant to all requests. e.g Info shared among every OAuth instance */
struct ConnectionConfig {
    string Consumerkey, 
    	ConsumerSecret, 
    	hostname, 
    	request_token_url, 
        authenticate_url,
    	oauth_ver, 
    	oauth_callback, 
    	request_token, 
        verifier,
    	oauth_token_secret,
        nickname;

    bool authenticated = false;

    bool hasSavedFile()
    {
        string filename = nickname + ".txt";
        ifstream infile(filename);
        return infile.good();
    }
};

/* OAuth represents a single web request. */
class OAuth {
    public: 
        OAuth(ConnectionConfig *connection, string, string);
        void printOAuth();
        void doRequest();
        void saveInfoToFile();
        string response;
    private: 
        ConnectionConfig *conn;
        OAuthParameters params;
        void BuildParameters();
        void splitHeaders(map<string, string>&, string);
        void setRequestTokenFromHeaders();
        void createAuthenticationURL();
        void exchangeTokens();
        void webRequest();
        string base64(const unsigned char*, int);
        string generateNonce();
        string generateTimeStamp();
        string createSignature();
        string urlencode(const string&);
        string char2hex(char);
        string HMACSHA1(string, string);
        static size_t requestDataCallback(char *, size_t, size_t, void *);
        void saveRequestResponse(char *);
        bool loadInfoFromFile(string);
        string strippedURL(string);
        string nonce, timeStamp, signature, method, url;
}; 