#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_log.h"
#include "esp_sleep.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_mac.h"

// Configuration Constants
static const char* TAG = "ESP_NOW_POWER_TEST";

// CONFIGURE YOUR PEER MAC ADDRESS HERE
static uint8_t peer_mac[ESP_NOW_ETH_ALEN];// Replace with actual receiver MAC

// Pre-shared key for encryption (16 bytes)
static uint8_t pmk_key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

// Local Master Key for encryption (16 bytes)  
static uint8_t lmk_key[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};


/* ---------- board detection ---------- */
static bool i_am_core2(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    return mac[5] == 0xA8;   // last byte of Core2
}

static void set_peer_mac(void)
{
    if (i_am_core2())
        memcpy(peer_mac, (uint8_t[]){0x4C,0x75,0x25,0xAD,0x0D,0x94}, 6); /* Atom */
    else
        memcpy(peer_mac, (uint8_t[]){0x2C,0xBC,0xBB,0x82,0x91,0xA8}, 6); /* Core2 */
}

// Test Configuration
typedef enum {
    ENCRYPT_OFF = 0,
    ENCRYPT_ON = 1
} encrypt_mode_t;

typedef enum {
    COMM_SIMPLEX = 0,    // Send only (original behavior)
    COMM_HALF_DUPLEX,    // Send, then wait for response
    COMM_FULL_DUPLEX     // Send and receive simultaneously
} comm_mode_t;

typedef struct {
    encrypt_mode_t encrypt;
    comm_mode_t comm_mode;
    size_t payload_size;
} test_config_t;

// Test cases - all combinations of encryption, communication mode, and payload sizes
static const test_config_t test_cases[] = {
    // Simplex (Send Only) Tests
    {ENCRYPT_OFF, COMM_SIMPLEX, 32},
    {ENCRYPT_OFF, COMM_SIMPLEX, 64}, 
    {ENCRYPT_OFF, COMM_SIMPLEX, 128},
    {ENCRYPT_OFF, COMM_SIMPLEX, 250},
    {ENCRYPT_ON, COMM_SIMPLEX, 32},
    {ENCRYPT_ON, COMM_SIMPLEX, 64},
    {ENCRYPT_ON, COMM_SIMPLEX, 128},
    {ENCRYPT_ON, COMM_SIMPLEX, 250},
    
    // Half-Duplex Tests (Send then Wait for Response)
    {ENCRYPT_OFF, COMM_HALF_DUPLEX, 32},
    {ENCRYPT_OFF, COMM_HALF_DUPLEX, 64}, 
    {ENCRYPT_OFF, COMM_HALF_DUPLEX, 128},
    {ENCRYPT_OFF, COMM_HALF_DUPLEX, 250},
    {ENCRYPT_ON, COMM_HALF_DUPLEX, 32},
    {ENCRYPT_ON, COMM_HALF_DUPLEX, 64},
    {ENCRYPT_ON, COMM_HALF_DUPLEX, 128},
    {ENCRYPT_ON, COMM_HALF_DUPLEX, 250},
    
    // Full-Duplex Tests (Simultaneous Send/Receive)
    {ENCRYPT_OFF, COMM_FULL_DUPLEX, 32},
    {ENCRYPT_OFF, COMM_FULL_DUPLEX, 64}, 
    {ENCRYPT_OFF, COMM_FULL_DUPLEX, 128},
    {ENCRYPT_OFF, COMM_FULL_DUPLEX, 250},
    {ENCRYPT_ON, COMM_FULL_DUPLEX, 32},
    {ENCRYPT_ON, COMM_FULL_DUPLEX, 64},
    {ENCRYPT_ON, COMM_FULL_DUPLEX, 128},
    {ENCRYPT_ON, COMM_FULL_DUPLEX, 250}
};

static const size_t num_test_cases = sizeof(test_cases) / sizeof(test_config_t);

// Global variables for test state management
static bool send_callback_received = false;
static bool recv_callback_received = false;
static esp_now_send_status_t send_status;
static uint8_t* received_data = NULL;
static int received_data_len = 0;
static size_t current_test_index = 0;
static bool full_duplex_active = false;

// RTC memory to persist test index across deep sleep
RTC_DATA_ATTR size_t rtc_test_index = 0;

// Forward declarations
static void start_full_duplex_sender_task(const test_config_t* test_config, size_t test_index);

// ESP-NOW send callback function
static void esp_now_send_cb(const uint8_t *mac_addr, esp_now_send_status_t status)
{
    ESP_LOGI(TAG, "Send callback: MAC=" MACSTR " Status=%s", 
             MAC2STR(mac_addr), 
             status == ESP_NOW_SEND_SUCCESS ? "SUCCESS" : "FAIL");
    
    send_status = status;
    send_callback_received = true;
}

// ESP-NOW receive callback function
static void esp_now_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len)
{
    ESP_LOGI(TAG, "Received callback: MAC=" MACSTR " RSSI=%d Len=%d", 
             MAC2STR(recv_info->src_addr), recv_info->rx_ctrl->rssi, len);
    
    // Store received data for analysis
    if (received_data) {
        free(received_data);
    }
    received_data = (uint8_t *)malloc(len);
    if (received_data) {
        memcpy(received_data, data, len);
        received_data_len = len;
        recv_callback_received = true;
        
        // Log first few bytes for verification
        ESP_LOGI(TAG, "Received data (first 8 bytes): %02X %02X %02X %02X %02X %02X %02X %02X",
                 data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
    }
}

// Initialize Wi-Fi in STA mode
static esp_err_t wifi_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE));
    
    ESP_LOGI(TAG, "WiFi initialized in STA mode, channel 1");
    return ESP_OK;
}

// Initialize ESP-NOW
static esp_err_t espnow_init(void)
{
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_send_cb(esp_now_send_cb));
    ESP_ERROR_CHECK(esp_now_register_recv_cb(esp_now_recv_cb));
    
    // Set primary master key if using encryption
    ESP_ERROR_CHECK(esp_now_set_pmk(pmk_key));
    
    ESP_LOGI(TAG, "ESP-NOW initialized with send and receive callbacks");
    return ESP_OK;
}

// Add peer with specified encryption setting
static esp_err_t add_peer(bool encrypt)
{
     esp_now_peer_info_t peer = {
     .channel = 1,
     .ifidx   = WIFI_IF_STA,
     .encrypt = encrypt,
 };
    memset(&peer, 0, sizeof(esp_now_peer_info_t));
    
    peer.channel = 1;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = encrypt;
    memcpy(peer.peer_addr, peer_mac, ESP_NOW_ETH_ALEN);
    
    if (encrypt) {
        memcpy(peer.lmk, lmk_key, 16);
    }
    
    esp_err_t ret = esp_now_add_peer(&peer);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add peer: %s", esp_err_to_name(ret));
        return ret;
    }
    
    ESP_LOGI(TAG, "Peer added successfully (encrypt=%s)", encrypt ? "ON" : "OFF");
    return ESP_OK;
}

// Remove all peers
static void remove_all_peers(void)
{
    esp_now_peer_info_t peer;
    esp_now_peer_num_t peer_num = {};
    
    esp_now_get_peer_num(&peer_num);
    if (peer_num.total_num > 0) {
        if (esp_now_fetch_peer(true, &peer) == ESP_OK) {
            esp_now_del_peer(peer.peer_addr);
            ESP_LOGI(TAG, "Peer removed");
        }
    }
}

// Create test payload
static void create_test_payload(uint8_t* data, size_t size, size_t test_index, uint8_t packet_type)
{
    // First byte indicates packet type (0x01=request, 0x02=response, 0x03=full-duplex)
    data[0] = packet_type;
    
    for (size_t i = 1; i < size; i++) {
        data[i] = (uint8_t)((test_index + i) & 0xFF);
    }
}

// Full-duplex sender task
static void full_duplex_sender_task(void *pvParameters)
{
    const test_config_t* test_config = (const test_config_t*)pvParameters;
    
    ESP_LOGI(TAG, "Full-duplex sender task started");
    
    // Send packets continuously for 5 seconds
    uint8_t* test_data = (uint8_t *)malloc(test_config->payload_size);
    if (!test_data) {
        ESP_LOGE(TAG, "Failed to allocate memory for full-duplex payload");
        vTaskDelete(NULL);
        return;
    }
    
    create_test_payload(test_data, test_config->payload_size, current_test_index, 0x03);
    
    TickType_t start_time = xTaskGetTickCount();
    TickType_t duration_ticks = pdMS_TO_TICKS(5000); // 5 seconds
    int packet_count = 0;
    
    while ((xTaskGetTickCount() - start_time) < duration_ticks && full_duplex_active) {
        esp_err_t ret = esp_now_send(peer_mac, test_data, test_config->payload_size);
        if (ret == ESP_OK) {
            packet_count++;
        }
        vTaskDelay(pdMS_TO_TICKS(100)); // Send every 100ms
    }
    
    ESP_LOGI(TAG, "Full-duplex sender task completed. Sent %d packets", packet_count);
    free(test_data);
    vTaskDelete(NULL);
}

// Start full-duplex sender task
static void start_full_duplex_sender_task(const test_config_t* test_config, size_t test_index)
{
    full_duplex_active = true;
    xTaskCreate(full_duplex_sender_task, "fd_sender", 4096, (void*)test_config, 5, NULL);
}

// Run simplex test (send only)
static esp_err_t run_simplex_test(const test_config_t* test_config, size_t test_index)
{
    ESP_LOGI(TAG, "Running SIMPLEX test (send only)");
    
    uint8_t* test_data = (uint8_t *)malloc(test_config->payload_size);
    if (!test_data) {
        return ESP_ERR_NO_MEM;
    }
    
    create_test_payload(test_data, test_config->payload_size, test_index, 0x01);
    
    // Reset callback state
    send_callback_received = false;
    send_status = ESP_NOW_SEND_FAIL;
    
    ESP_LOGI(TAG, "Sending ESP-NOW packet...");
    esp_err_t ret = esp_now_send(peer_mac, test_data, test_config->payload_size);
    free(test_data);
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Send error: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Wait for send callback
    int timeout_ms = 3000;
    int elapsed_ms = 0;
    while (!send_callback_received && elapsed_ms < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(10));
        elapsed_ms += 10;
    }
    
    if (!send_callback_received) {
        ESP_LOGE(TAG, "Send callback timeout!");
        return ESP_ERR_TIMEOUT;
    }
    
    return send_status == ESP_NOW_SEND_SUCCESS ? ESP_OK : ESP_FAIL;
}

// Run half-duplex test (send then wait for response)
static esp_err_t run_half_duplex_test(const test_config_t* test_config, size_t test_index)
{
    ESP_LOGI(TAG, "Running HALF-DUPLEX test (send then wait for response)");
    
    uint8_t* test_data = (uint8_t *)malloc(test_config->payload_size);
    if (!test_data) {
        return ESP_ERR_NO_MEM;
    }
    
    create_test_payload(test_data, test_config->payload_size, test_index, 0x01);
    
    // Reset callback states
    send_callback_received = false;
    recv_callback_received = false;
    send_status = ESP_NOW_SEND_FAIL;
    
    ESP_LOGI(TAG, "Sending request packet...");
    esp_err_t ret = esp_now_send(peer_mac, test_data, test_config->payload_size);
    free(test_data);
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Send error: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Wait for send callback
    int timeout_ms = 3000;
    int elapsed_ms = 0;
    while (!send_callback_received && elapsed_ms < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(10));
        elapsed_ms += 10;
    }
    
    if (!send_callback_received || send_status != ESP_NOW_SEND_SUCCESS) {
        ESP_LOGE(TAG, "Send failed or timeout!");
        return ESP_ERR_TIMEOUT;
    }
    
    ESP_LOGI(TAG, "Request sent successfully, waiting for response...");
    
    // Wait for response
    timeout_ms = 5000;
    elapsed_ms = 0;
    while (!recv_callback_received && elapsed_ms < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(10));
        elapsed_ms += 10;
    }
    
    if (!recv_callback_received) {
        ESP_LOGW(TAG, "No response received within timeout");
        return ESP_ERR_TIMEOUT;
    }
    
    ESP_LOGI(TAG, "Response received successfully (%d bytes)", received_data_len);
    return ESP_OK;
}

// Run full-duplex test (simultaneous send and receive)
static esp_err_t run_full_duplex_test(const test_config_t* test_config, size_t test_index)
{
    ESP_LOGI(TAG, "Running FULL-DUPLEX test (simultaneous send/receive for 5 seconds)");
    
    // Reset callback states
    recv_callback_received = false;
    
    // Start sender task
    start_full_duplex_sender_task(test_config, test_index);
    
    // Monitor for 5 seconds while sender task is running
    TickType_t start_time = xTaskGetTickCount();
    TickType_t duration_ticks = pdMS_TO_TICKS(5000);
    int recv_count = 0;
    
    while ((xTaskGetTickCount() - start_time) < duration_ticks) {
        if (recv_callback_received) {
            recv_count++;
            recv_callback_received = false; // Reset for next packet
            ESP_LOGI(TAG, "Received packet #%d during full-duplex", recv_count);
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    // Stop full-duplex mode
    full_duplex_active = false;
    vTaskDelay(pdMS_TO_TICKS(200)); // Allow sender task to complete
    
    ESP_LOGI(TAG, "Full-duplex test completed. Received %d packets", recv_count);
    return ESP_OK;
}

// Get communication mode string
static const char* get_comm_mode_string(comm_mode_t mode)
{
    switch (mode) {
        case COMM_SIMPLEX: return "SIMPLEX";
        case COMM_HALF_DUPLEX: return "HALF-DUPLEX";
        case COMM_FULL_DUPLEX: return "FULL-DUPLEX";
        default: return "UNKNOWN";
    }
}

// Run a single test case
static esp_err_t run_test_case(const test_config_t* test_config, size_t test_index)
{
    ESP_LOGI(TAG, "=== Starting Test %d/%d ===", (int)(test_index + 1), (int)num_test_cases);
    ESP_LOGI(TAG, "Mode: %s, Encryption: %s, Payload Size: %d bytes", 
             get_comm_mode_string(test_config->comm_mode),
             test_config->encrypt ? "ON" : "OFF", 
             (int)test_config->payload_size);
    
    // Initialize WiFi and ESP-NOW
    ESP_ERROR_CHECK(wifi_init());
    ESP_ERROR_CHECK(espnow_init());
    
    // Add peer with current encryption setting
    ESP_ERROR_CHECK(add_peer(test_config->encrypt));
    
    esp_err_t test_result = ESP_FAIL;
    
    // Run test based on communication mode
    switch (test_config->comm_mode) {
        case COMM_SIMPLEX:
            test_result = run_simplex_test(test_config, test_index);
            break;
        case COMM_HALF_DUPLEX:
            test_result = run_half_duplex_test(test_config, test_index);
            break;
        case COMM_FULL_DUPLEX:
            test_result = run_full_duplex_test(test_config, test_index);
            break;
    }
    
    if (test_result == ESP_OK) {
        ESP_LOGI(TAG, "Test PASSED");
    } else {
        ESP_LOGW(TAG, "Test completed with issues (this may be normal for some test types)");
    }
    
    ESP_LOGI(TAG, "=== Test %d/%d Complete ===", (int)(test_index + 1), (int)num_test_cases);
    
    // Cleanup
    remove_all_peers();
    esp_now_deinit();
    esp_wifi_stop();
    esp_wifi_deinit();
    
    if (received_data) {
        free(received_data);
        received_data = NULL;
    }
    
    return ESP_OK;
}

// Main application entry point
void app_main(void)
{
    ESP_LOGI(TAG, "ESP-NOW Comprehensive Power Consumption Test Starting...");
    ESP_LOGI(TAG, "Testing: Simplex, Half-Duplex, and Full-Duplex modes");
    
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    set_peer_mac();
    /* NEW PRINT HERE */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    ESP_LOGI(TAG, "My MAC: %02X:%02X:%02X:%02X:%02X:%02X  peer: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             peer_mac[0], peer_mac[1], peer_mac[2],
             peer_mac[3], peer_mac[4], peer_mac[5]);
    // Get current test index from RTC memory
    current_test_index = rtc_test_index;
    
    ESP_LOGI(TAG, "Current test index: %d (Total tests: %d)", 
             (int)current_test_index, (int)num_test_cases);
    
    // Check if all tests are complete
    if (current_test_index >= num_test_cases) {
        ESP_LOGI(TAG, "=== ALL TESTS COMPLETED ===");
        ESP_LOGI(TAG, "Total tests run: %d", (int)num_test_cases);
        ESP_LOGI(TAG, "Tests included:");
        ESP_LOGI(TAG, "  - 8 Simplex tests (send only)");
        ESP_LOGI(TAG, "  - 8 Half-duplex tests (send then wait for response)");
        ESP_LOGI(TAG, "  - 8 Full-duplex tests (simultaneous send/receive)");
        ESP_LOGI(TAG, "Test sequence finished. Stopping.");
        
        // Reset test index for next run
        rtc_test_index = 0;
        
        // Go to sleep indefinitely or restart tests
        ESP_LOGI(TAG, "Entering deep sleep indefinitely. Reset to restart tests.");
        esp_deep_sleep_start();
        return;
    }
    
    // Run current test case
    const test_config_t* current_test = &test_cases[current_test_index];
    esp_err_t test_result = run_test_case(current_test, current_test_index);
    
    if (test_result != ESP_OK) {
        ESP_LOGE(TAG, "Test %d failed with error: %s", 
                 (int)current_test_index, esp_err_to_name(test_result));
    }
    
    // Increment test index for next wake-up
    rtc_test_index = current_test_index + 1;
    
    // Print sleep message
    ESP_LOGI(TAG, "Test finished for %s mode, %s encryption, payload size %d. Entering deep sleep for 10 seconds.",
             get_comm_mode_string(current_test->comm_mode),
             current_test->encrypt ? "WITH" : "WITHOUT",
             (int)current_test->payload_size);
    
    ESP_LOGI(TAG, "Next test: %d/%d", (int)(rtc_test_index + 1), (int)num_test_cases);
    
    // Sleep for 10 seconds before next test
    esp_sleep_enable_timer_wakeup(10 * 1000000); // 10 seconds in microseconds
    esp_deep_sleep_start();
}