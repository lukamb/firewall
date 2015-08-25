/*
 * Projekt: Firewall
 * Soubor: pdscli.c
 * Autor: Lukas Ambroz
 * Popis: Hlavni soubor user space aplikace
 */

#include <stdio.h>
#include <string.h>
#include "types.h"
#include "scanner.yy.h"
#include "parser.tab.h"

/*
 * Vypise napovedu
 */
void print_help(void) {
    printf("Usage: pdscli -p        - Prints stored firewall rules\n");
    printf("       pdscli -a <rule> - Adds specified rule (enclosed in quotes)\n");
    printf("       pdscli -f <file> - Loads rules from file\n");
    printf("       pdscli -d <id>   - Removes rule with given id\n");
    printf("rule: <id> <action> <protocol> from <srcip> to <dstip> [src-port <srcport>] [dst-port <dstport>]\n");
    printf("      id                - rule number\n");
    printf("      action            - allow | deny\n");
    printf("      protocol          - tcp | udp | icmp | ip\n");
    printf("      srcip | dstip     - IPv4 address | any\n");
    printf("      srcport | dstport - port number\n");
    printf("Note: Kernel module pdsfw.ko must be loaded first\n");
}

/*
 * Odesle data kernel space aplikaci
 */
int send_proc(char *s) {
    FILE *pf;
    
    pf = fopen("/proc/pdsfw-xambro03", "w");
    if (pf == NULL) {
        fprintf(stderr, "Cannot open /proc/pdsfw-xambro03 for writing\n");
        return 1;
    }
    
    fprintf(pf, "%s", s);
    fclose(pf);
    return 0;
}

/*
 * Odesle prikaz pro pridani pravidla
 */
int send_add_rule(pdsfw_rule_str_t *rule) {
    char buffer[200] = "";
    
    strcat(buffer, rule->id);
    strcat(buffer, " ");
    strcat(buffer, rule->action);
    strcat(buffer, " ");
    strcat(buffer, rule->protocol);
    strcat(buffer, " ");
    strcat(buffer, rule->srcip);
    strcat(buffer, " ");
    strcat(buffer, rule->dstip);
    strcat(buffer, " ");
    
    if ((rule->is_dst_port == 0 && rule->port1[0] != '\0') ||
        (rule->port1[0] != '\0' && rule->port2[0] != '\0'))
        strcat(buffer, rule->port1);
    else
        strcat(buffer, "0");
    strcat(buffer, " ");
    
    if (rule->is_dst_port == 1 && rule->port2[0] == '\0')
        strcat(buffer, rule->port1);
    else if (rule->port1[0] != '\0' && rule->port2[0] != '\0')
        strcat(buffer, rule->port2);
    else
        strcat(buffer, "0");
    strcat(buffer, "\n");
    
    return send_proc(buffer);
}

/*
 * Odesle prikaz ke smazani pravidla
 */
int send_delete_rule(unsigned id) {
    char buffer[10];
    sprintf(buffer, "d%u\n", id);
    return send_proc(buffer);
}

/*
 * Zpracuje nacteny radek s pravidlem
 */
int process_line(char *line) {
    pdsfw_init_rule_str(&pdsfw_flex_rule);
    yy_scan_string(line);
    
    if (yyparse() == 0)
        return send_add_rule(&pdsfw_flex_rule);
    else {
        fprintf(stderr, "Rule syntax is not correct\n");
        return 1;
    }
}

/*
 * Zpracuje pravidla v zadanem souboru
 */
int process_file(char *file) {
    FILE *fr;
    char buffer[200];
    
    fr = fopen(file, "r");
    if (fr == NULL) {
        fprintf(stderr, "Cannot open input file for reading\n");
        return 1;
    }
    
    while (fgets(buffer, 200, fr) != NULL)
        process_line(buffer);
    
    fclose(fr);
    return 0;
}

/*
 * Nacte a vypise pravidla firewallu
 */
int read_rules(void) {
    FILE *pf;
    char token[20];
    char ch;
    int i = 0;
    pdsfw_rule_str_t rule;
    
    pf = fopen("/proc/pdsfw-xambro03", "r");
    if (pf == NULL) {
        fprintf(stderr, "Cannot open /proc/pdsfw-xambro03 for reading\n");
        return 1;
    }
    
    pdsfw_print_head();
    
    while (1) {
        pdsfw_init_rule_str(&rule);
        while (((ch = fgetc(pf)) == ' ') || (ch == '\n'));
        if (ch == EOF) break;
        
        // id
        i = 0;
        token[i++] = ch;
        while (((ch = fgetc(pf)) != EOF) && (ch != ' '))
            token[i++] = ch;
        token[i] = '\0';
        strcpy(rule.id, token);
        
        // action
        i = 0;
        while (((ch = fgetc(pf)) != EOF) && (ch != ' '))
            token[i++] = ch;
        token[i] = '\0';
        strcpy(rule.action, token);
        
        // protocol
        i = 0;
        while (((ch = fgetc(pf)) != EOF) && (ch != ' '))
            token[i++] = ch;
        token[i] = '\0';
        strcpy(rule.protocol, token);
        
        // srcip
        i = 0;
        while (((ch = fgetc(pf)) != EOF) && (ch != ' '))
            token[i++] = ch;
        token[i] = '\0';
        strcpy(rule.srcip, token);
        
        // dstip
        i = 0;
        while (((ch = fgetc(pf)) != EOF) && (ch != ' '))
            token[i++] = ch;
        token[i] = '\0';
        strcpy(rule.dstip, token);
        
        // srcport
        i = 0;
        while (((ch = fgetc(pf)) != EOF) && (ch != ' '))
            token[i++] = ch;
        token[i] = '\0';
        if (strcmp(token, "0") != 0)
            strcpy(rule.port1, token);
        
        // dstport
        i = 0;
        while (((ch = fgetc(pf)) != EOF) && (ch != ' ') && (ch != '\n'))
            token[i++] = ch;
        token[i] = '\0';
        if (strcmp(token, "0") != 0) {
            rule.is_dst_port = 1;
            if (rule.port1[0] == '\0')
                strcpy(rule.port1, token);
            else
                strcpy(rule.port2, token);
        }
        
        pdsfw_print_rule_str(&rule);
        
        if (ch == EOF) break;
    }
    
    fclose(pf);
    return 0;
}

/*
 * Hlavni funkce programu
 */
int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "-p") == 0)
        read_rules();
    else if (argc == 3 && strcmp(argv[1], "-a") == 0)
        process_line(argv[2]);
    else if (argc == 3 && strcmp(argv[1], "-f") == 0)
        process_file(argv[2]);
    else if (argc == 3 && strcmp(argv[1], "-d") == 0)
        send_delete_rule(atoi(argv[2]));
    else
        print_help();
    
    return 0;
}
