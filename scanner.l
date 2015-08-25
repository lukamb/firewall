/*
 * Projekt: Firewall
 * Soubor: scanner.l
 * Autor: Lukas Ambroz
 * Popis: Popis scanneru pro nacitani pravidel
 */

%option header-file="scanner.yy.h"
%option outfile="scanner.yy.c"
%option noyywrap
%{
#include <stdio.h>
#include <string.h>
#include "types.h"
#include "parser.tab.h"

void install_value() {
    if (pdsfw_flex_rule.id[0] == '\0') {
        strncpy(pdsfw_flex_rule.id, yytext, PDSFW_NUM_MAX_LENGTH - 1);
        pdsfw_flex_rule.id[PDSFW_NUM_MAX_LENGTH - 1] = 0;
        return;
    }
    if (pdsfw_flex_rule.action[0] == '\0') {
        strncpy(pdsfw_flex_rule.action, yytext, PDSFW_ACTION_MAX_LENGTH - 1);
        pdsfw_flex_rule.action[PDSFW_ACTION_MAX_LENGTH - 1] = 0;
        return;
    }
    if (pdsfw_flex_rule.protocol[0] == '\0') {
        strncpy(pdsfw_flex_rule.protocol, yytext, PDSFW_PROTOCOL_MAX_LENGTH - 1);
        pdsfw_flex_rule.protocol[PDSFW_PROTOCOL_MAX_LENGTH - 1] = 0;
        return;
    }
    if (pdsfw_flex_rule.srcip[0] == '\0') {
        strncpy(pdsfw_flex_rule.srcip, yytext, PDSFW_IP_MAX_LENGTH - 1);
        pdsfw_flex_rule.srcip[PDSFW_IP_MAX_LENGTH - 1] = 0;
        return;
    }
    if (pdsfw_flex_rule.dstip[0] == '\0') {
        strncpy(pdsfw_flex_rule.dstip, yytext, PDSFW_IP_MAX_LENGTH - 1);
        pdsfw_flex_rule.dstip[PDSFW_IP_MAX_LENGTH - 1] = 0;
        return;
    }
    if (pdsfw_flex_rule.port1[0] == '\0') {
        strncpy(pdsfw_flex_rule.port1, yytext, PDSFW_NUM_MAX_LENGTH - 1);
        pdsfw_flex_rule.port1[PDSFW_NUM_MAX_LENGTH - 1] = 0;
        return;
    }
    if (pdsfw_flex_rule.port2[0] == '\0') {
        strncpy(pdsfw_flex_rule.port2, yytext, PDSFW_NUM_MAX_LENGTH - 1);
        pdsfw_flex_rule.port2[PDSFW_NUM_MAX_LENGTH - 1] = 0;
        return;
    }
}
%}

digit   [0-9]
octet   {digit}{1,3}

%%

{digit}{1,5}                             {install_value(); return(NUMBER);}
allow|deny                               {install_value(); return(ACTION);}
tcp|udp|icmp|ip                          {install_value(); return(PROTOCOL);}
from                                     return(FROM);
to                                       return(TO);
{octet}\.{octet}\.{octet}\.{octet}|any   {install_value(); return(IP);}
src-port                                 return(SRCPORT);
dst-port                                 return(DSTPORT);
[ \t\r\n]
.                                        return (int) yytext[0];

%%
