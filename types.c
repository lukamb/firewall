/*
 * Projekt: Firewall
 * Soubor: types.c
 * Autor: Lukas Ambroz
 * Popis: Soubor obsahujici definici zakladnich typu a konstant
 */

#include "types.h"

/*
 * Globalni promenna pro nacteni dat flexem
 */
pdsfw_rule_str_t pdsfw_flex_rule;

/*
 * Prototypy funkci
 */
void pdsfw_init_rule_str(pdsfw_rule_str_t *rule);
void pdsfw_print_rule_str(pdsfw_rule_str_t *rule);
void pdsfw_print_head();

/*
 * Inicializace pravidla
 */
void pdsfw_init_rule_str(pdsfw_rule_str_t *rule) {
    rule->id[0] = '\0';
    rule->action[0] = '\0';
    rule->protocol[0] = '\0';
    rule->srcip[0] = '\0';
    rule->dstip[0] = '\0';
    rule->port1[0] = '\0';
    rule->port2[0] = '\0';
    rule->is_dst_port = 0;
}

/*
 * Vypis pravidla
 */
void pdsfw_print_rule_str(pdsfw_rule_str_t *rule) {
    printf("%-6s", rule->id);
    printf("%-8s", rule->action);
    
    if (strcmp(rule->srcip, "any") == 0)
        printf("*               ");
    else
        printf("%-16s", rule->srcip);
    
    if ((rule->is_dst_port == 0 && rule->port1[0] != '\0') ||
        (rule->port1[0] != '\0' && rule->port2[0] != '\0'))
        printf("%-9s", rule->port1);
    else
        printf("*        ");
    
    if (strcmp(rule->dstip, "any") == 0)
        printf("*               ");
    else
        printf("%-16s", rule->dstip);
    
    if (rule->is_dst_port == 1 && rule->port2[0] == '\0')
        printf("%-9s", rule->port1);
    else if (rule->port1[0] != '\0' && rule->port2[0] != '\0')
        printf("%-9s", rule->port2);
    else
        printf("*        ");
    
    printf("%s\n", rule->protocol);
}

/*
 * Vypis hlavicky s nazvy sloupcu pro atributy pravidel
 */
void pdsfw_print_head() {
    printf("id    action  srcip           srcport  dstip           dstport  protocol\n");
}
