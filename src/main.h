#ifndef _MAIN_H_
#define _MAIN_H_

#include <Arduino.h>
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "base64.h"
#include "mbedtls/md.h"

std::string EncodePassword(std::string challenge, std::string salt);
void ConnectionReset();
void ParseOBSResponse(char *payload);
void webSocketEvent(WStype_t type, uint8_t *payload, size_t length);
void setup();
void SetScene(String scene);
void loop();

#endif