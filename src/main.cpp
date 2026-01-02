#include <Arduino.h>

#include "crypto_engine.h"
#include "helper_fun.h"
#include "wifi_config.h"


static uint8_t plaintext_block[AES_BLOCK_SIZE];
static uint8_t tag[AES_TAG_SIZE];
static uint8_t iv[AES_IV_SIZE];

//--------- Time tracking variables -----------
static uint32_t timing_AES[REPETITIONS];
uint16_t timing_count = 0;
int elapsed = 0;
uint64_t t_end = 0;
uint64_t t_start = 0;
uint64_t start_communication = 0;
uint64_t end_communication = 0;
//---------------------------------------------

int total_received = 0;
int decrypt_ok = 0;
int decrypt_fail = 0;

Message msg;

void setup() {
    Serial.begin(115200);

    //monitorMemory();
    Serial.printf("AES_BLOCK_SIZE = %d bytes\n", AES_BLOCK_SIZE);
    Serial.printf("MQTT_MAX_PACKET_SIZE = %d bytes\n", MQTT_MAX_PACKET_SIZE);
    Serial.printf("REPETITIONS = %d\n\n", REPETITIONS);   
    
    connectWiFi();
    setupMQTT();
    connectMQTT();

    
    #ifdef DEVICE_ROLE_SUBSCRIBER

        mqttClient.setCallback(mqttCallback);
        mqttClient.subscribe(MQTT_TOPIC);
        ESP_LOGI("MAIN", "Started as SUBSCRIBER");

    #endif
    
    #ifdef DEVICE_ROLE_PUBLISHER
        
        start_communication = esp_timer_get_time();
        
        ESP_LOGI("MAIN", "Started as PUBLISHER");
        memset(plaintext_block, 0xFF, AES_BLOCK_SIZE);

        int counter = 1; //debaging purpose

        for (int i = 0; i < REPETITIONS; i++) {

            sprintf((char*)plaintext_block, "MSG_ID AES: %d", counter);
            //print_ASCII("Plaintext: ", plaintext_block, AES_BLOCK_SIZE);
            counter++;

            //-- start timing---
            elapsed = 0;
            t_start = esp_timer_get_time();
            //------------------

            aes_encrypt(plaintext_block, iv, msg.ciphertext, tag);
            
            //-- end timing---
            t_end = esp_timer_get_time();
            elapsed = t_end - t_start;
            //------------------


            //print_hex("Auth Tag: ", tag, AES_TAG_SIZE);
            //print_hex("Ciphertext: ", ciphertext_block, CHACHA_BLOCK_SIZE);

            //compose the rest of the message
            memcpy(msg.iv, iv, AES_IV_SIZE);
            memcpy(msg.tag, tag, AES_TAG_SIZE);

            if (!mqttClient.publish(MQTT_TOPIC, (uint8_t*)&msg, sizeof(Message), false)) {
                //Serial.println("MQTT publish failed");
            } else {
                //Serial.println("Published encrypted message to MQTT");
            }

            //float bytes_per_sec = (AES_BLOCK_SIZE * 1e6) / (t_end - t_start);
            timing_AES[timing_count++] = elapsed;
        }
            
        end_communication = esp_timer_get_time();
        Serial.printf("Total communication time: %lu us\n", end_communication - start_communication);
        analyze_timing(timing_AES, timing_count);


    #endif
    

    //monitorMemory();
}

bool flage = 0;
void loop() {

    #ifdef DEVICE_ROLE_SUBSCRIBER

        if(flage == 0){
            start_communication = esp_timer_get_time();
            flage = 1;
        }

        mqttClient.loop(); // Maintain MQTT connection

        if (timing_count == REPETITIONS) {
            end_communication = esp_timer_get_time();
            Serial.printf("Total communication time: %lu us\n", end_communication - start_communication);
            analyze_timing(timing_AES, timing_count);
            timing_count++; //to prevent re-entering
        }   
    #endif

    
}

void mqttCallback(char* topic, byte* payload, unsigned int length) {
    //Serial.print("Message arrived on topic: ");
    //Serial.println(topic);

    //Serial.print("Payload length: ");
    //Serial.println(length);

    // Example: copy binary payload
    if (length == sizeof(Message)) { 
        //Serial.println("saving...");
        total_received ++;
    }else{
        //Serial.println("Invalid payload size");
        return;
    }

    Message* msg = (Message*)payload;

    // Access the fields:
    // Serial.print("iv: ");
    // for (int i = 0; i < AES_IV_SIZE; i++) {
    //     Serial.print(msg->iv[i], HEX); Serial.print(" ");
    // }
    // Serial.println();

    // Serial.print("Tag: ");
    // for (int i = 0; i < AES_TAG_SIZE; i++) {
    //     Serial.print(msg->tag[i], HEX); Serial.print(" ");
    // }
    // Serial.println();

    // Serial.print("Ciphertext: ");
    // for (int i = 0; i < AES_BLOCK_SIZE; i++) {
    //     Serial.print(msg->ciphertext[i], HEX); Serial.print(" ");
    // }
    // Serial.println();

    //Serial.print("Decrypting...");
    bool done = false;

    //-- start timing---
    elapsed = 0;
    t_start = esp_timer_get_time();
    //------------------

    done = aes_decrypt(msg->ciphertext, msg->iv, msg->tag, plaintext_block);

    //-- end timing---
    t_end = esp_timer_get_time();
    elapsed = t_end - t_start;
    timing_AES[timing_count++] = elapsed;
    //------------------

    if (done) {
        //print_ASCII("Plaintext: ", plaintext_block, AES_BLOCK_SIZE);
        decrypt_ok ++;
    } else {
        //Serial.println("Decryption failed!");
        decrypt_fail ++;
    }

}

