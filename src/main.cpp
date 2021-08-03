#include "main.h"
#include <Arduino.h>
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "base64.h"
#include "mbedtls/md.h"

#define DEBUG

#ifdef DEBUG
#define TRACE(x) Serial.print(x);
#else
#define TRACE(x)
#endif

/* Put your SSID & Password */
const char *ssid = "";     // Enter SSID here
const char *password = ""; // Enter Password here

WebSocketsClient webSocket;

/* Put IP Address details */
IPAddress local_ip(192, 168, 0, 10);
IPAddress gateway(192, 168, 0, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress primaryDNS(8, 8, 8, 8);   //optional
IPAddress secondaryDNS(8, 8, 4, 4); //optional

StaticJsonDocument<2000> doc;

uint8_t InputPin = 2;
uint8_t LEDPin = 12;
bool PreviousState = LOW;

// OBS Event IDs
enum OBSEvent
{
    None,
    GetAuthRequired,
    Authenticate,
    GetCurrentScene,
    SetCurrentScene
};

// OBS Server details
struct OBS
{
    const char *IP_Address = "192.168.0.20"; // OSB computer
    const int Port = 4444;                   // OSB port
    const std::string Password = "password"; // OSB password
    const char *TargetScene = "Microscope";  // OSB scene
    bool Authorised = false;  // true when OBS authorises the connection
    bool Authorising = false; // true when sending OBS authorisation hash
    bool Connected = false;   // true when OBS authorises the connection
    const std::string messageID = "12345"; // ID sent with web socket packet
    String PreviousScene = "Webcam"; // This is updated automatically on connection
    OBSEvent Event;
} obs;

byte *sha256(const char *payload)
{
    // http://www.esp32learning.com/code/using-sha-256-with-an-esp32.php
    byte *shaResult = new byte[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    const size_t payloadLength = strlen(payload);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *)payload, payloadLength);
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);
    return shaResult;
}

std::string EncodePassword(std::string challenge, std::string salt)
{
    macaron::Base64 b64encode;

    std::string message = obs.Password + salt;

    // Create a SHA256 hash for password + server salt
    static const byte *hash = sha256(message.c_str());

    static const std::string secret = b64encode.Encode(hash, 32);

    // Create a SHA256 hash for base64 secret + server challenge
    const std::string message2 = secret + challenge;

    static const byte *auth_response_hash = sha256(message2.c_str());

    static const std::string auth_response = b64encode.Encode(auth_response_hash, 32);

    TRACE("\npassword:");
    TRACE(obs.Password.c_str());
    TRACE("\nsalt:");
    TRACE(salt.c_str());
    TRACE("\nchallenge:");
    TRACE(challenge.c_str());
    TRACE("\nb64_encoded_hash:");
    TRACE(secret.c_str());
    TRACE("\nb64_encoded_auth:");
    TRACE(auth_response.c_str());

    return auth_response;
}

void ConnectionReset()
{
    obs.Authorised = false;
    obs.Authorising = false;
    obs.Connected = false;
    obs.Event = None;
}

void ParseOBSResponse(char *payload)
{
    TRACE("Payload-------------------\n");
    TRACE(payload);
    TRACE("--------------------------\n");
    TRACE("Parsing Response\n");

    // Deserialize the JSON document
    DeserializationError error = deserializeJson(doc, payload);

    // Test if parsing succeeds.
    if (error)
    {
        TRACE(F("deserializeJson() failed: "));
        TRACE(error.f_str());
        return;
    }
    else
    {
        JsonObject root = doc.as<JsonObject>();
        for (JsonObject::iterator it = root.begin(); it != root.end(); ++it)
        {
            // Parse the response based on the CurrentMessage ID
            switch (obs.Event)
            {
            case GetCurrentScene:
                // Check if response contains the name field
                if (strcmp(it->key().c_str(), "name") == 0)
                {
                    obs.PreviousScene = String(it->value().as<char *>());
                    obs.Connected = true;
                }
                break;

            case SetCurrentScene:
                // Check if response contains the from-scene field
                if (strcmp(it->key().c_str(), "from-scene") == 0)
                {
                    obs.PreviousScene = String(it->value().as<char *>());
                }
                break;

            case Authenticate:
                // Check for ok response after Authenticate
                if (strcmp(it->key().c_str(), "status") == 0)
                {
                    if (obs.Authorising)
                    {
                        if (root["status"] == "ok")
                        {
                            obs.Authorised = true;
                            obs.Authorising = false;

                            // get the current scene
                            obs.Event = GetCurrentScene;
                            webSocket.sendTXT("{\"request-type\": \"GetCurrentScene\", \"message-id\":\"12345\"}");
                        }
                    }
                }
                break;

            case GetAuthRequired:
                // Check for response from GetAuthRequired
                if (strcmp(it->key().c_str(), "authRequired") == 0)
                {
                    if (root["authRequired"] == true)
                    {
                        std::string challenge = root["challenge"];
                        std::string salt = root["salt"];
                        std::string hashedpassword = EncodePassword(challenge, salt);

                        //TRACE("\nResponse Hash: ");
                        //TRACE(hashedpassword.c_str());

                        // Send JSON Packet

                        StaticJsonDocument<200> responsedoc;
                        responsedoc["request-type"] = "Authenticate";
                        responsedoc["message-id"] = obs.messageID;
                        responsedoc["auth"] = hashedpassword;
                        String output;

                        obs.Authorising = true;
                        obs.Event = Authenticate;
                        serializeJsonPretty(responsedoc, output);
                        TRACE("\nAuth Response\n");
                        TRACE(output.c_str());
                        webSocket.sendTXT(output);
                    }
                    else
                    {
                        // Auth not required
                        obs.Authorised = true;
                    }
                    break;
                }
            default:
                TRACE("Unknown Event");
            }
        }

        TRACE("\n");
    }
}

void webSocketEvent(WStype_t type, uint8_t *payload, size_t length)
{
    switch (type)
    {
    case WStype_DISCONNECTED:
        TRACE("OBS: Disconnected\n");
        ConnectionReset();
        break;
    case WStype_CONNECTED:
        TRACE("OBS: Connected\n");
        if (!obs.Authorised)
        {
            TRACE("Testing for Authorization")
            obs.Event = GetAuthRequired;
            webSocket.sendTXT("{\"request-type\": \"GetAuthRequired\", \"message-id\":\"12345\"}");
        }

    case WStype_PING:
        TRACE("OBS: Pinged\n");
    case WStype_PONG:
        TRACE("OBS: Pong\n");
        break;
    case WStype_BIN:
        TRACE("OBS: Bin Request\n");
        break;
    case WStype_TEXT:
        ParseOBSResponse((char *)payload);
        break;
    case WStype_ERROR:
        break;
    case WStype_FRAGMENT_TEXT_START:
    case WStype_FRAGMENT_BIN_START:
    case WStype_FRAGMENT:
    case WStype_FRAGMENT_FIN:
        break;
    }
}

void setup()
{
#ifdef DEBUG
    Serial.begin(115200);
    while (!Serial)
        continue;
#endif

    TRACE("Booting Microscope OBS Controller:");

    // Set up IO pins
    pinMode(InputPin, INPUT);
    pinMode(LEDPin, OUTPUT);
    digitalWrite(LEDPin, LOW);

    // Connect to WiFi
    TRACE("Connecting to Wifi");
    WiFi.mode(WIFI_STA);

    if (!WiFi.config(local_ip, gateway, subnet, primaryDNS, secondaryDNS))
    {
        TRACE("Wifi Failed to configure");
    }

    WiFi.begin(ssid, password);

    // Wait for connection
    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        TRACE(".");
    }
    TRACE("\n");
    TRACE("Connected to ");
    TRACE(ssid);
    TRACE("\nIP address: ");
    TRACE(WiFi.localIP());
    TRACE("\n");

    // server address, port and URL
    webSocket.begin(obs.IP_Address, obs.Port, "/");

    // event handler
    webSocket.onEvent(webSocketEvent);

    // try ever 5000 again if connection has failed
    webSocket.setReconnectInterval(2000);
}

void SetScene(String scene)
{
    StaticJsonDocument<200> doc;
    doc["request-type"] = "SetCurrentScene";
    doc["message-id"] = obs.messageID;
    doc["scene-name"] = scene;
    String output;
    obs.Event = SetCurrentScene;
    serializeJsonPretty(doc, output);
    webSocket.sendTXT(output);
}

void loop()
{
    webSocket.loop();

    if (obs.Authorised && obs.Connected)
    {
        digitalWrite(LEDPin, HIGH);

        if (digitalRead(InputPin) == HIGH && PreviousState == LOW)
        {
            // Revert to previous scene
            TRACE("Input State: High");
            PreviousState = HIGH;

            // Send JSON Packet
            SetScene(obs.PreviousScene);
            delay(500);
        }
        if (digitalRead(InputPin) == LOW && PreviousState == HIGH)
        {
            // Set OBS to the target scene
            TRACE("Input State: Low");
            PreviousState = LOW;

            // Send JSON Packet
            SetScene(obs.TargetScene);
            delay(500);
        }
    }
    else
    {
        digitalWrite(LEDPin, LOW);
    }
}
