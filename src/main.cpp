#include <Arduino.h>

#include "crypto_engine.h"
#include "helper_fun.h"
#include "wifi_config.h"


static uint8_t plaintext_block[AES_BLOCK_SIZE];
static uint8_t tag[AES_TAG_SIZE];
static uint8_t iv[AES_IV_SIZE];

Message msg;

void setup() {
    Serial.begin(115200);
    
    connectWiFi();
    setupMQTT();
    connectMQTT();

    #ifdef DEVICE_ROLE_SUBSCRIBER
        mqttClient.setCallback(mqttCallback);
        mqttClient.subscribe(MQTT_TOPIC);
        ESP_LOGI("MAIN", "Started as SUBSCRIBER");
    #endif

    #ifdef DEVICE_ROLE_PUBLISHER
        ESP_LOGI("MAIN", "Started as PUBLISHER");
        memset(plaintext_block, 0xFF, AES_BLOCK_SIZE);

        int counter = 1; //debaging purpose

        for (int i = 0; i < 200; i++) {

            sprintf((char*)plaintext_block, "HELLO ESP32 AES %d", counter);
            print_ASCII("Plaintext: ", plaintext_block, AES_BLOCK_SIZE);
            counter++;

            aes_encrypt(plaintext_block, iv, msg.ciphertext, tag);
            print_hex("Auth Tag: ", tag, AES_TAG_SIZE);
            //print_hex("Ciphertext: ", ciphertext_block, CHACHA_BLOCK_SIZE);

            //compose the rest of the message
            memcpy(msg.iv, iv, AES_IV_SIZE);
            memcpy(msg.tag, tag, AES_TAG_SIZE);

            if (!mqttClient.publish(MQTT_TOPIC, (uint8_t*)&msg, sizeof(Message), false)) {
                Serial.println("MQTT publish failed");
            } else {
                Serial.println("Published encrypted message to MQTT");
            }
        }
        
    #endif
    
    
    //monitorMemory();
}


void loop() {

    #ifdef DEVICE_ROLE_SUBSCRIBER
        mqttClient.loop(); // Maintain MQTT connection
    #endif
    
}



void mqttCallback(char* topic, byte* payload, unsigned int length) {
    Serial.print("Message arrived on topic: ");
    Serial.println(topic);

    Serial.print("Payload length: ");
    Serial.println(length);

    // Example: copy binary payload
    if (length == sizeof(Message)) { 
        Serial.println("saving...");
    }else{
        Serial.println("Invalid payload size");
        return;
    }

    Message* msg = (Message*)payload;

    // Access the fields:
    Serial.print("iv: ");
    for (int i = 0; i < AES_IV_SIZE; i++) {
        Serial.print(msg->iv[i], HEX); Serial.print(" ");
    }
    Serial.println();

    Serial.print("Tag: ");
    for (int i = 0; i < AES_TAG_SIZE; i++) {
        Serial.print(msg->tag[i], HEX); Serial.print(" ");
    }
    Serial.println();

    Serial.print("Ciphertext: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        Serial.print(msg->ciphertext[i], HEX); Serial.print(" ");
    }
    Serial.println();

    Serial.print("Decrypting...");
    bool done;
    done = aes_decrypt(msg->ciphertext, msg->iv, msg->tag, plaintext_block);

    if (done) {
        print_ASCII("Plaintext: ", plaintext_block, AES_BLOCK_SIZE);
    } else {
        Serial.println("Decryption failed!");
    }

}

