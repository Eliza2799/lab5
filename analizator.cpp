#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <unistd.h>
#include "analizator.h"

struct ifparam ifp;
__u8 buff[ETH_FRAME_LEN];
const char* interface_name = nullptr;

// Функция индикации превышения параметров
void alert_threshold(const char* param_name, float current_value, float threshold) {
    // Цветной вывод
    printf("\033[1;31m"); // Красный цвет
    printf("\n=== ПРЕВЫШЕНИЕ ПАРАМЕТРА ===\n");
    printf("Параметр: %s\n", param_name);
    printf("Текущее значение: %.2f\n", current_value);
    printf("Пороговое значение: %.2f\n", threshold);
    printf("\033[0m"); // Сброс цвета
    
    // Звуковое оповещение
    for(int i = 0; i < 3; i++) {
        printf("\a"); // Звуковой сигнал
        fflush(stdout);
        usleep(200000); // Пауза 200 мс
    }
    
    // Визуализация превышения
    printf("График:\n[");
    int val = (int)((current_value/threshold)*50);
    for(int i = 0; i < 50; i++) {
        if(i < val) printf("\033[1;31m#\033[0m");
        else printf("-");
    }
    printf("]\n\n");
    
    // Логирование в файл
    FILE* log = fopen("network_monitor.log", "a");
    if(log) {
        time_t now = time(NULL);
        fprintf(log, "[%s] Превышение %s: %.2f (порог: %.2f)\n", 
                ctime(&now), param_name, current_value, threshold);
        fclose(log);
    }
}

void mode_off(int sig) {
    if(interface_name && getifconf((__u8 *)interface_name, &ifp, PROMISC_MODE_OFF) < 0) {
        perror("getifconf");
    }
    exit(0);
}

void process_packet(struct ifparam* ifp, int packet_size) {
    static int packet_count = 0;
    static time_t last_time = time(NULL);
    
    packet_count++;
    
    // Проверка скорости пакетов
    time_t current_time = time(NULL);
    if(current_time != last_time) {
        float packets_per_sec = (float)packet_count;
        if(packets_per_sec > 1000) { // Порог 1000 пакетов/сек
            alert_threshold("скорости пакетов", packets_per_sec, 1000.0);
        }
        packet_count = 0;
        last_time = current_time;
    }
    
    // Проверка размера пакета
    if(packet_size > ifp->mtu) {
        alert_threshold("размера пакета", (float)packet_size, (float)ifp->mtu);
    }
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        printf("Использование: %s <интерфейс>\n", argv[0]);
        system("ip -o link show | awk -F': ' '{print $2}'");
        return -1;
    }

    interface_name = argv[1];
    __u32 num = 0;
    int eth0_if, rec = 0;
    struct iphdr ip;
    struct tcphdr tcp;
    struct ethhdr eth;
    static struct sigaction act;

    if(getifconf((__u8 *)interface_name, &ifp, PROMISC_MODE_ON) < 0) {
        perror("getifconf");
        return -1;
    }

    printf("Мониторинг интерфейса: %s\n", interface_name);
    printf("IP: %s\n", inet_ntoa(*(struct in_addr*)&ifp.ip));
    printf("Маска: %s\n", inet_ntoa(*(struct in_addr*)&ifp.mask));
    printf("MTU: %d\n", ifp.mtu);
    printf("Индекс: %d\n", ifp.index);

    if((eth0_if = getsock_recv(ifp.index)) < 0) {
        perror("getsock_recv");
        return -1;
    }

    act.sa_handler = mode_off;
    sigfillset(&(act.sa_mask));
    sigaction(SIGINT, &act, NULL);

    printf("\nНачало мониторинга... (Ctrl+C для выхода)\n");

    while(true) {
        memset(buff, 0, ETH_FRAME_LEN);
        rec = recvfrom(eth0_if, (char*)buff, ifp.mtu + 18, 0, NULL, NULL);

        if(rec < 0 || rec > ETH_FRAME_LEN) {
            perror("recvfrom");
            break;
        }

        process_packet(&ifp, rec);

        memcpy((void*)&eth, buff, ETH_HLEN);
        memcpy((void*)&ip, buff + ETH_HLEN, sizeof(struct iphdr));
        
        if(ip.version != 4) continue;

        if(ip.protocol == IPPROTO_TCP) {
            memcpy((void*)&tcp, buff + ETH_HLEN + ip.ihl * 4, sizeof(struct tcphdr));
            
            printf("\nПакет #%u\n", num++);
            printf("Отправитель: %s:%d\n", 
                  inet_ntoa(*(struct in_addr*)&ip.saddr), ntohs(tcp.source));
            printf("Получатель: %s:%d\n", 
                  inet_ntoa(*(struct in_addr*)&ip.daddr), ntohs(tcp.dest));
            printf("Размер: %d байт\n", ntohs(ip.tot_len));
        }
    }

    mode_off(0);
    return 0;
}
