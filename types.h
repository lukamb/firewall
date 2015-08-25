/*
 * Projekt: Firewall
 * Soubor: types.h
 * Autor: Lukas Ambroz
 * Popis: Soubor obsahujici definici zakladnich typu a konstant
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <string.h>

/*
 * Delky jednotlivych poli pravidel
 */
#define PDSFW_NUM_MAX_LENGTH 6
#define PDSFW_ACTION_MAX_LENGTH 6
#define PDSFW_PROTOCOL_MAX_LENGTH 5
#define PDSFW_IP_MAX_LENGTH 16

/*
 * Pravidlo pro nacteni ze vstupu
 */
typedef struct pdsfw_rule_str {
    char id[PDSFW_NUM_MAX_LENGTH];
    char action[PDSFW_ACTION_MAX_LENGTH];
    char protocol[PDSFW_PROTOCOL_MAX_LENGTH];
    char srcip[PDSFW_IP_MAX_LENGTH];
    char dstip[PDSFW_IP_MAX_LENGTH];
    char port1[PDSFW_NUM_MAX_LENGTH];
    char port2[PDSFW_NUM_MAX_LENGTH];
    int is_dst_port;  // Priznak, zda byl zadan dst-port kvuli parsovani
} pdsfw_rule_str_t;

/*
 * Globalni promenna pro nacteni dat flexem
 */
extern pdsfw_rule_str_t pdsfw_flex_rule;

/*
 * Inicializace pravidla
 */
void pdsfw_init_rule_str(pdsfw_rule_str_t *rule);

/*
 * Vypis pravidla
 */
void pdsfw_print_rule_str(pdsfw_rule_str_t *rule);

/*
 * Vypis hlavicky s nazvy sloupcu pro atributy pravidel
 */
void pdsfw_print_head();

#endif
