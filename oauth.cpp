/* Desmond Preston 2015

Compile with: sudo g++ -std=c++11 oauth.cpp -lcrypto -lcurl

Oauth implementation

Create request in 2 steps:
1. Create new ConnectionConfig and assign values to Consumerkey, ConsumerSecret, hostname, request_token_url, oauth_ver, oauth_callback, auth_token
2. Create new Oauth object with parameters:
    Connection (ConnectionConfig); this is the ConnectionConfig object you created in step 1 or another connection config already created.
    httpMethod (string); the method to use for http request (GET, POST).
    url (string); url to make request to.
*/

#include "stdio.h"
#include <iostream>
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
    string Consumerkey, ConsumerSecret, hostname, request_token_url, oauth_ver, oauth_callback, auth_token;
};

/* OAuth represents a single web request. */
class OAuth {
    public: 
        OAuth(ConnectionConfig connection, string, string);
        void printOAuth();
    private: 
        ConnectionConfig conn;
        OAuthParameters params;
        void BuildParameters(const string& requestToken = "", const string& httpMethod = "", const string& pin = "");
        void newToken();
        void webRequest();
        string base64(const unsigned char*, int);
        string generateNonce();
        string generateTimeStamp();
        string createSignature(const string& requestTokenSecret = "");
        string urlencode(const string&);
        string char2hex(char);
        string HMACSHA1(string, string);
        string nonce, timeStamp, signature, method, url;
}; 

OAuth::OAuth(ConnectionConfig ConnectionToUse, string httpMethod, string urlToUse) 
{
    conn = ConnectionToUse;
    method = httpMethod;
    url = urlToUse;
    nonce = generateNonce();
    timeStamp = generateTimeStamp(); 
    BuildParameters();
    //printOAuth();
    webRequest();
}

void OAuth::newToken()
{
    /*
        Create a new token. This method must be called before any other requests are made. 
        If a new request is made and there is no token readily available, this method is called beforehand.
    */
}

void OAuth::webRequest()
{
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl)
    {
        struct curl_slist *chunk = NULL;
        string header = "Authorization: OAuth";
        for (OAuthParameters::const_iterator it = params.begin(); it != params.end(); it++)
        {
            header = header + " " + it->first + "=" + "\"" + it->second  + "\",";
        }
        header = header.substr(0, header.size()-1);

        chunk = curl_slist_append(chunk, header.c_str());

        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, header.c_str());

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res) );
            curl_easy_cleanup(curl);
            curl_slist_free_all(chunk);
        } else {
            cout << "SUCCESS";
        }
    }
}

void OAuth::BuildParameters(const string& requestToken, const string& requestTokenSecret, const string& pin)
{
    //Set first params provided from connection settings
    params["oauth_consumer_key"] = conn.Consumerkey;
    params["oauth_nonce"] = nonce;
    params["oauth_timestamp"] = timeStamp;
    params["oauth_version"] = conn.oauth_ver;
    params["oauth_signature_method"] = "HMAC-SHA1";

    if (!requestToken.empty())
    {
        params["oauth_token"] = requestToken;
    }

    if (!pin.empty())
    {
        params["oauth_verifier"] = pin;
    }

    string signature = createSignature(requestTokenSecret);
    params["oauth_signature"] = signature;
}

string OAuth::createSignature(const string& requestTokenSecret)
{
    /* 
        1. Create a single string of query params from the params map
        2. Generate key from ConsumerSecret and requestTokenSecret (if it exists)
        3. Generate signature base from http method, base Url, and the single string of query params
        4. Generate signature from key and signature base
    */

    //Parameters need to be converted to a single string to be used as query parameters in the url
    string normalizedParams;

    for (OAuthParameters::const_iterator it = params.begin(); it != params.end(); it++)
    {
        if (normalizedParams.size() > 0)
        {
            normalizedParams += "&";
        }
        normalizedParams += it->first + "=" + it->second;
    }

    string key = conn.ConsumerSecret + "&";
    string signatureBase = method + "&" + urlencode(url) + "&" + urlencode(normalizedParams);

    cout << "Normalized Params: \n" << normalizedParams << endl;
    cout << "Base string: \n" << signatureBase << endl;

    string signature = HMACSHA1(key, signatureBase);

    cout << signature << endl;

    return urlencode(signature);
}

void OAuth::printOAuth()
{
    cout << "Nonce: " << nonce << endl
         << "Timestamp: " << timeStamp << endl
         << "=================================" << endl
         << "Connection Details: " << endl
         << "Consumer Key: " << conn.Consumerkey << endl
         << "Consumer Secret: " << conn.ConsumerSecret << endl
         << "Hostname: " << conn.hostname << endl
         << "Request Token URL: " << conn.request_token_url << endl
         << "OAuth Version: " << conn.oauth_ver << endl
         << "OAuth CallBack: " << conn.oauth_callback << endl;
}

string OAuth::generateNonce()
{
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string nonce;

    srand(time(0));

    for (int i = 0; i <= 31; i++) 
    {
        nonce += alphanum[rand() % (sizeof(alphanum)-1)];
    }

    return nonce;
}

string OAuth::generateTimeStamp()
{
    time_t t = time(0);
    return to_string(t);
}

string OAuth::base64(const unsigned char *input, int length)
{
    /*
        Convert to base64
    */
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  return string((const char*)buff);
}

// char2hex and urlencode from http://www.zedwood.com/article/111/cpp-urlencode-function
// modified according to http://oauth.net/core/1.0a/#encoding_parameters
string OAuth::char2hex( char dec )
{
    char dig1 = (dec&0xF0)>>4;
    char dig2 = (dec&0x0F);
    if ( 0<= dig1 && dig1<= 9) dig1+=48;    //0,48 in ascii
    if (10<= dig1 && dig1<=15) dig1+=65-10; //A,65 in ascii
    if ( 0<= dig2 && dig2<= 9) dig2+=48;
    if (10<= dig2 && dig2<=15) dig2+=65-10;

    string r;
    r.append( &dig1, 1);
    r.append( &dig2, 1);
    return r;
}

string OAuth::urlencode(const string &c)
{
    /*
        Encode according to OAuth encoding standard. Not typical URL encoding.
    */
    string escaped;
    int max = c.length();
    for(int i=0; i<max; i++)
    {
        if ( (48 <= c[i] && c[i] <= 57) ||//0-9
            (65 <= c[i] && c[i] <= 90) ||//ABC...XYZ
            (97 <= c[i] && c[i] <= 122) || //abc...xyz
            (c[i]=='~' || c[i]=='-' || c[i]=='_' || c[i]=='.')
            )
        {
            escaped.append( &c[i], 1);
        }
        else
        {
            escaped.append("%");
            escaped.append( char2hex(c[i]) );//converts char 255 to string "FF"
        }
    }
    return escaped;
}

string OAuth::HMACSHA1(string key, string data)
{
    /*
        Hash key using data with HMAC-SHA1 then base64 encode the result 
    */

    unsigned char strDigest[1024];
    CHMAC_SHA1 objHMACSHA1;

    memset(strDigest, 0, 1024);

    objHMACSHA1.HMAC_SHA1((unsigned char*)data.c_str(), data.length(), (unsigned char*) key.c_str(), key.length(), strDigest);

    return base64(strDigest, strlen((char*)strDigest));
}

int main() {
    // For testing

    // 1. Create a new connection config instance for Twitter. This will be used for all OAuth connections related to Twitter
    ConnectionConfig Twitter;
    Twitter.Consumerkey = "uvSDDZJW7XiG64akUzMgS44tF";
    Twitter.ConsumerSecret = "CCu9u5pRUOtXeO9VsitmgVSL4RbQwbiWX06aBLkaRsJRVt6EKL";
    Twitter.hostname = "http://twitter.com";
    Twitter.request_token_url = "https://api.twitter.com/oauth/request_token";
    Twitter.oauth_ver = "1.0";
    Twitter.oauth_callback = "oob";

    // 2. Create a new connection using Twitter connection config
    OAuth test(Twitter, "POST", "https://api.twitter.com/oauth/request_token");
    return 0;
}

