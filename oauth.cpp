#include "oauth.h"

OAuth::OAuth(ConnectionConfig *ConnectionToUse, string httpMethod, string urlToUse)
{
    conn = ConnectionToUse;
    method = httpMethod;
    url = urlToUse;
    nonce = generateNonce();
    timeStamp = generateTimeStamp();

    BuildParameters();
    //printOAuth();
    if (conn->request_token.empty())
    {
        setRequestTokenFromHeaders();
        createAuthenticationURL();
    }
    else if (!conn->authenticated && !conn->verifier.empty())
    {
        exchangeTokens();
    }
    else 
    {
        webRequest();
    }
}

/**
    UTILS for mostly data manipulation
    START
**/

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

void OAuth::splitHeaders(map<string, string>& headersMap, string s)
{
    string headerDelimiter = "&", valuePairDelimiter = "=", singleHeader = "", name = "", value = "";
    size_t start = 0, end = s.find(headerDelimiter), separator;

    while (end != string::npos)
    {
        singleHeader = s.substr(start, end-start);
        separator = singleHeader.find(valuePairDelimiter)+1;
        name = singleHeader.substr(0, separator-1);
        value = singleHeader.substr(separator);
        headersMap[name] = value;

        start = end+1;
        end = s.find(headerDelimiter, start+1);
    }

    // While loop breaks before last header can be added
    singleHeader = s.substr(start, end-start);
    separator = singleHeader.find(valuePairDelimiter)+1;
    name = singleHeader.substr(0, separator-1);
    value = singleHeader.substr(separator);
    headersMap[name] = value;
}

string OAuth::strippedURL(string u)
{
    return u.substr(0, u.find("?")-1);
}

/**
    END UTILS
**/


void OAuth::setRequestTokenFromHeaders()
{
    map<string, string> headers;

    webRequest();
    splitHeaders(headers, response);

    cout << headers["oauth_token"] << endl;
    conn->request_token = headers["oauth_token"];
    conn->oauth_token_secret = headers["oauth_token_secret"];
}

void OAuth::createAuthenticationURL()
{
    cout << "In your browser, please go to:\n" << conn->authenticate_url + "?" + response <<endl; 
    cout << "Enter the pin here: ";
    cin >> conn->verifier;
}

void OAuth::exchangeTokens()
{
    url = url + "?oauth_verifier=" + conn->verifier;
    
    //Exchanging oauth_token and oauth_token_secret for validated tokens.
    setRequestTokenFromHeaders();

    conn->authenticated = true;
}

void OAuth::saveRequestResponse(char *res)
{
    response = res;
    cout << response << endl;
}

/*
    Callback for webRequest() response
*/
size_t OAuth::requestDataCallback(char *ptr, size_t size, size_t nmemb, void *f)
{
    static_cast<OAuth*>(f)->saveRequestResponse(ptr);

    return size *nmemb;
}

/* 
    Creates and executes web request using current params and url
*/
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
        //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        if (method == "POST")
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, header.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, requestDataCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res) );
            curl_easy_cleanup(curl);
            curl_slist_free_all(chunk);
        } else {
            //cout << "SUCCESS";
        }
    }
}

void OAuth::BuildParameters()
{
    //Set first params provided from connection settings
    params["oauth_consumer_key"] = conn->Consumerkey;
    params["oauth_nonce"] = nonce;
    params["oauth_timestamp"] = timeStamp;
    params["oauth_version"] = conn->oauth_ver;
    params["oauth_signature_method"] = "HMAC-SHA1";
    params["oauth_callback"] = conn->oauth_callback;

    if (!conn->request_token.empty())
    {
        params["oauth_token"] = conn->request_token;
    }

    if (!conn->verifier.empty() && !conn->authenticated)
    {
        params["oauth_verifier"] = conn->verifier;
    }

    string signature = createSignature();
    params["oauth_signature"] = signature;
}

string OAuth::createSignature()
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

    string key = conn->ConsumerSecret + "&";

    if (!conn->oauth_token_secret.empty()) 
    {
        key.append(conn->oauth_token_secret);
    }

    string signatureBase = method + "&" + urlencode(url) + "&" + urlencode(normalizedParams);

    string signature = HMACSHA1(key, signatureBase);

    return urlencode(signature);
}

void OAuth::printOAuth()
{
    cout << "Nonce: " << nonce << endl
         << "Timestamp: " << timeStamp << endl
         << "=================================" << endl
         << "Connection Details: " << endl
         << "Consumer Key: " << conn->Consumerkey << endl
         << "Consumer Secret: " << conn->ConsumerSecret << endl
         << "Hostname: " << conn->hostname << endl
         << "Request Token URL: " << conn->request_token_url << endl
         << "OAuth Version: " << conn->oauth_ver << endl
         << "OAuth CallBack: " << conn->oauth_callback << endl;
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
  //BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);

  BIO_write(b64, input, length);
  BIO_flush(b64);
  char* output;
  BIO_get_mem_data(bmem, &output);

  return string((const char*)output);
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

