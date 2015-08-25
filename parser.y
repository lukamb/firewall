/*
 * Projekt: Firewall
 * Soubor: parser.y
 * Autor: Lukas Ambroz
 * Popis: Popis parseru pro nacitani pravidel
 */

%defines

%{
#include "types.h"
#include "scanner.yy.h"
%}

%token NUMBER
%token ACTION
%token PROTOCOL
%token FROM
%token TO
%token IP
%token SRCPORT
%token DSTPORT

%%

rule : NUMBER ACTION PROTOCOL FROM IP TO IP ports

ports :
      | SRCPORT NUMBER
      | DSTPORT NUMBER {pdsfw_flex_rule.is_dst_port = 1;}
      | SRCPORT NUMBER DSTPORT NUMBER {pdsfw_flex_rule.is_dst_port = 1;}
     
%%

int yyerror(char *s) {
    //fprintf(stderr, "%s\n", s);
    return 1;
}
