/*
 * Projekt: Firewall
 * Soubor: pdsfw.c
 * Autor: Lukas Ambroz
 * Popis: Kernel modul implementujici firewall
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("pdsfw");
MODULE_AUTHOR("Lukas Ambroz");

#define MAX_SIZE 1024
#define FILE_NAME "pdsfw-xambro03"

/*
 * Cisla protokolu
 */
#define PDSFW_PROTO_IP 0
#define PDSFW_PROTO_ICMP 1
#define PDSFW_PROTO_TCP 6
#define PDSFW_PROTO_UDP 17

/*
 * Akce pro dany paket
 */
#define PDSFW_ALLOW 1
#define PDSFW_DENY 0

/*
 * Konstanty pro zpracovani pravidel
 */
const char *PDSFW_ACTION_ALLOW = "allow";
const char *PDSFW_ACTION_DENY = "deny";
const char *PDSFW_PROTOCOL_TCP = "tcp";
const char *PDSFW_PROTOCOL_UDP = "udp";
const char *PDSFW_PROTOCOL_ICMP = "icmp";
const char *PDSFW_PROTOCOL_IP = "ip";
const char *PDSFW_IP_ANY = "any";

/*
 * Pravidlo pro ulozeni v seznamu pravidel a filtraci
 */
typedef struct pdsfw_rule {
    unsigned id;
    int action;
    unsigned protocol;
    unsigned srcip;
    unsigned dstip;
    unsigned srcport;
    unsigned dstport;
    struct pdsfw_rule *next;
} pdsfw_rule_t;

/*
 * Seznam pravidel
 */
typedef struct pdsfw_rule_list {
    pdsfw_rule_t *first;
    int count;
} pdsfw_rule_list_t;

/*
 * Globalni promenna pro ulozeni seznamu pravidel
 */
pdsfw_rule_list_t rule_list;

/*
 * Globalni promenne pro praci s procfs
 */
unsigned long procf_buffer_pos;
static char buf[MAX_SIZE];
static unsigned long procBuffSize = 0; // Velikost dat v bufferu
static struct proc_dir_entry *proc;

/*
 * Globalni promenne pro praci s pakety
 */
static struct nf_hook_ops nfho;

/*
 * Alokuje a inicializuje nove pravidlo
 */
pdsfw_rule_t *pdsfw_new_rule(void) {
    pdsfw_rule_t *result;
    
    result = vmalloc(sizeof(pdsfw_rule_t));
    result->srcport = 0;
    result->dstport = 0;
    result->next = NULL;
    
    return result;
}

/*
 * Inicializace seznamu pravidel
 */
void pdsfw_init_list(pdsfw_rule_list_t *list) {
    list->first = NULL;
    list->count = 0;
}

/*
 * Prida pravidlo do seznamu na spravne misto nebo nahradi jiz existujici
 */
void pdsfw_add_rule(pdsfw_rule_list_t *list, pdsfw_rule_t *rule) {
    pdsfw_rule_t *tmp = NULL;
    pdsfw_rule_t *prev = NULL;
    
    // Prazdny seznam
    if (list->first == NULL) {
        list->first = rule;
        rule->next = NULL;
        list->count++;
        return;
    }
    
    // Nahrazeni na prvni pozici
    if (rule->id == list->first->id) {
        tmp = list->first;
        list->first = rule;
        rule->next = tmp->next;
        vfree(tmp);
        return;
    }
    
    // Vlozeni na prvni pozici
    if (rule->id < list->first->id) {
        tmp = list->first;
        list->first = rule;
        rule->next = tmp;
        list->count++;
        return;
    }
    
    tmp = list->first->next;
    prev = list->first;
    while (tmp != NULL) {
        
        // Vlozeni na vyhledane misto
        if (tmp->id > rule->id) {
            prev->next = rule;
            rule->next = tmp;
            list->count++;
            return;
        }
        
        // Nahrazeni na vyhledanem miste
        if (tmp->id == rule->id) {
            prev->next = rule;
            rule->next = tmp->next;
            vfree(tmp);
            return;
        }
        
        prev = tmp;
        tmp = tmp->next;
    }
    
    // Pridani na konec
    prev->next = rule;
    rule->next = NULL;
    list->count++;
}

/*
 * Odstrani zadane pravidlo ze seznamu
 */
void pdsfw_remove_rule(pdsfw_rule_list_t *list, unsigned id) {
    pdsfw_rule_t *tmp = NULL;
    pdsfw_rule_t *prev = NULL;
    
    // Prazdny seznam
    if (list->first == NULL)
        return;
    
    // Odstraneni prvniho prvku
    if (list->first->id == id) {
        tmp = list->first;
        list->first = tmp->next;
        list->count--;
        vfree(tmp);
        return;
    }
    
    // Odstraneni prvku ve zbytku seznamu
    tmp = list->first->next;
    prev = list->first;
    while (tmp != NULL) {
        if (tmp->id == id) {
            prev->next = tmp->next;
            list->count--;
            vfree(tmp);
            return;
        }
        prev = tmp;
        tmp = tmp->next;
    }
}

/*
 * Odstrani vsechna pravidla ze seznamu
 */
void pdsfw_remove_all(pdsfw_rule_list_t *list) {
    pdsfw_rule_t *tmp = NULL;
    
    list->count = 0;
    while (list->first != NULL) {
        tmp = list->first;
        list->first = tmp->next;
        vfree(tmp);
    }
}

/*
 * Prevod retezce s IP adresou na unsigned v sitovem usporadani
 */
unsigned str_to_nip(char *ip) {
    unsigned char tmp[4];
    unsigned long val = 0;
    char *pch;
    
    pch = strsep(&ip, ".");
    val = simple_strtoul(pch, NULL, 0);
    memcpy(&(tmp[0]), &val, 1);
    pch = strsep(&ip, ".");
    val = simple_strtoul(pch, NULL, 0);
    memcpy(&(tmp[1]), &val, 1);
    pch = strsep(&ip, ".");
    val = simple_strtoul(pch, NULL, 0);
    memcpy(&(tmp[2]), &val, 1);
    pch = strsep(&ip, ".");
    val = simple_strtoul(pch, NULL, 0);
    memcpy(&(tmp[3]), &val, 1);
    
    return *((unsigned *) tmp);
}

/*
 * Prevod IP adresy v sitovem usporadani na retezec
 */
void nip_to_str(unsigned ip, char *dst) {
    unsigned char tmp[4];
    memcpy(tmp, &ip, 4);
    sprintf(dst, "%d.%d.%d.%d", tmp[0], tmp[1], tmp[2], tmp[3]);
}

/*
 * Zpracuje cteni dat user space aplikaci
 */
static ssize_t procRead(struct file *fp, char *buffer, size_t len, loff_t *offset) {
    char token[20];
    int k;
    pdsfw_rule_t *rule;
    static int finished = 0;
    procf_buffer_pos = 0;
    
    if (finished) {
        finished = 0;
        return 0;
    }
    finished = 1;
    
    rule = rule_list.first;
    for (k = 0; k < rule_list.count; k++) {
        
        // id
        sprintf(token, "%u", rule->id);
        memcpy(buf + procf_buffer_pos, token, strlen(token));
        procf_buffer_pos += strlen(token);
        memcpy(buf + procf_buffer_pos, " ", 1);
        procf_buffer_pos++;
        
        // action
        if (rule->action == PDSFW_ALLOW)
            strcpy(token, PDSFW_ACTION_ALLOW);
        else
            strcpy(token, PDSFW_ACTION_DENY);
        memcpy(buf + procf_buffer_pos, token, strlen(token));
        procf_buffer_pos += strlen(token);
        memcpy(buf + procf_buffer_pos, " ", 1);
        procf_buffer_pos++;
        
        // protocol
        if (rule->protocol == PDSFW_PROTO_TCP)
            strcpy(token, PDSFW_PROTOCOL_TCP);
        else if (rule->protocol == PDSFW_PROTO_UDP)
            strcpy(token, PDSFW_PROTOCOL_UDP);
        else if (rule->protocol == PDSFW_PROTO_ICMP)
            strcpy(token, PDSFW_PROTOCOL_ICMP);
        else
            strcpy(token, PDSFW_PROTOCOL_IP);
        memcpy(buf + procf_buffer_pos, token, strlen(token));
        procf_buffer_pos += strlen(token);
        memcpy(buf + procf_buffer_pos, " ", 1);
        procf_buffer_pos++;
        
        // srcip
        if (rule->srcip == 0)
            strcpy(token, PDSFW_IP_ANY);
        else
            nip_to_str(rule->srcip, token);
        memcpy(buf + procf_buffer_pos, token, strlen(token));
        procf_buffer_pos += strlen(token);
        memcpy(buf + procf_buffer_pos, " ", 1);
        procf_buffer_pos++;
        
        // dstip
        if (rule->dstip == 0)
            strcpy(token, PDSFW_IP_ANY);
        else
            nip_to_str(rule->dstip, token);
        memcpy(buf + procf_buffer_pos, token, strlen(token));
        procf_buffer_pos += strlen(token);
        memcpy(buf + procf_buffer_pos, " ", 1);
        procf_buffer_pos++;
        
        // srcport
        sprintf(token, "%u", rule->srcport);
        memcpy(buf + procf_buffer_pos, token, strlen(token));
        procf_buffer_pos += strlen(token);
        memcpy(buf + procf_buffer_pos, " ", 1);
        procf_buffer_pos++;
        
        // dstport
        sprintf(token, "%u", rule->dstport);
        memcpy(buf + procf_buffer_pos, token, strlen(token));
        procf_buffer_pos += strlen(token);
        memcpy(buf + procf_buffer_pos, "\n", 1);
        procf_buffer_pos++;
        
        rule = rule->next;
    }
    
    if (copy_to_user(buffer, buf, procf_buffer_pos)) {
        return -EFAULT;
    }
    
    return procf_buffer_pos;
}

/*
 * Zpracuje zapis dat user space aplikaci
 */
static ssize_t procWrite(struct file *file, const char *buffer, size_t count, loff_t *off) {
    int i, j;
    pdsfw_rule_t *rule;
    char token[20];
    unsigned x;
    procf_buffer_pos = 0;
    x = 0;
    
    if(count > MAX_SIZE)
        procBuffSize = MAX_SIZE;
    else
        procBuffSize = count;
    if(copy_from_user(buf, buffer, procBuffSize))
        return -EFAULT;
    
    // Odstraneni pravidla
    if (buf[procf_buffer_pos] == 'd') {
        i = procf_buffer_pos + 1;
        j = 0;
        
        while ((buf[i] != ' ') && (buf[i] != '\n')) {
            token[j] = buf[i];
            i++;
            j++;
        }
        token[j] = '\0';
        x =  (unsigned) simple_strtoul(token, NULL, 0);
        
        pdsfw_remove_rule(&rule_list, x);
        return procBuffSize;
    }
    
    // Pridani pravidla
    rule = pdsfw_new_rule();
    i = procf_buffer_pos; j = 0;
    
    // id
    while (buf[i] != ' ')
        token[j++] = buf[i++];
    i++;
    token[j] = '\0';
    rule->id = (unsigned) simple_strtoul(token, NULL, 0);
    
    // action
    j = 0;
    while (buf[i] != ' ')
        token[j++] = buf[i++];
    i++;
    token[j] = '\0';
    if (strcmp(token, PDSFW_ACTION_ALLOW) == 0)
        rule->action = PDSFW_ALLOW;
    else
        rule->action = PDSFW_DENY;
    
    // protocol
    j = 0;
    while (buf[i] != ' ')
        token[j++] = buf[i++];
    i++;
    token[j] = '\0';
    if (strcmp(token, PDSFW_PROTOCOL_TCP) == 0)
        rule->protocol = PDSFW_PROTO_TCP;
    else if (strcmp(token, PDSFW_PROTOCOL_UDP) == 0)
        rule->protocol = PDSFW_PROTO_UDP;
    else if (strcmp(token, PDSFW_PROTOCOL_ICMP) == 0)
        rule->protocol = PDSFW_PROTO_ICMP;
    else
        rule->protocol = PDSFW_PROTO_IP;
    
    // srcip
    j = 0;
    while (buf[i] != ' ')
        token[j++] = buf[i++];
    i++;
    token[j] = '\0';
    if (strcmp(token, PDSFW_IP_ANY) == 0)
        rule->srcip = 0;
    else
        rule->srcip = str_to_nip(token);
    
    // dstip
    j = 0;
    while (buf[i] != ' ')
        token[j++] = buf[i++];
    i++;
    token[j] = '\0';
    if (strcmp(token, PDSFW_IP_ANY) == 0)
        rule->dstip = 0;
    else
        rule->dstip = str_to_nip(token);
    
    // srcport
    j = 0;
    while (buf[i] != ' ')
        token[j++] = buf[i++];
    i++;
    token[j] = '\0';
    rule->srcport = (unsigned) simple_strtoul(token, NULL, 0);
    
    // dstport
    j = 0;
    while (buf[i] != ' ' && buf[i] != '\n')
        token[j++] = buf[i++];
    i++;
    token[j] = '\0';
    rule->dstport = (unsigned) simple_strtoul(token, NULL, 0);
    
    pdsfw_add_rule(&rule_list, rule);
    return procBuffSize;
}

/*
 * Otevreni procfs souboru
 */
int procOpen(struct inode *inode, struct file *fp) {
    try_module_get(THIS_MODULE);
    return 0;
}

/*
 * Uzavreni procfs souboru
 */
int procClose(struct inode *inode, struct file *fp) {
    module_put(THIS_MODULE);
    return 0;
}

/*
 * Nastaveni procfs souboru
 */
static struct file_operations procFops = {
    read: procRead,
    write: procWrite,
    open: procOpen,
    release: procClose,
};

/*
 * Funkce pro filtrovani paketu
 */
unsigned int hook_fnc(unsigned int hooknum, struct sk_buff *skb,
                      const struct net_device *in, const struct net_device *out,
                      int (*okfn)(struct sk_buff *)) {
    
    // Nacitane hodnoty pro klasifikaci
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    unsigned int srcip;
    unsigned int dstip;
    unsigned int srcport = 0;
    unsigned int dstport = 0;
    pdsfw_rule_t *rule;
    
    // Ziskani hodnot
    ip_header = (struct iphdr *) skb_network_header(skb);
    srcip = (unsigned int) ip_header->saddr;
    dstip = (unsigned int) ip_header->daddr;
    if (ip_header->protocol == PDSFW_PROTO_UDP) {
        udp_header = (struct udphdr *) (skb_transport_header(skb) + 20);
        srcport = (unsigned int) ntohs(udp_header->source);
        dstport = (unsigned int) ntohs(udp_header->dest);
    } else if (ip_header->protocol == PDSFW_PROTO_TCP) {
        tcp_header = (struct tcphdr *) (skb_transport_header(skb) + 20);
        srcport = (unsigned int) ntohs(tcp_header->source);
        dstport = (unsigned int) ntohs(tcp_header->dest);
    }
    
    // Klasifikace pruchodem seznamem pravidel
    rule = rule_list.first;
    while (rule != NULL) {
        // srcip
        if (rule->srcip != 0) {
            if (rule->srcip != srcip) {
                rule = rule->next;
                continue;
            }
        }
        
        // dstip
        if (rule->dstip != 0) {
            if (rule->dstip != dstip) {
                rule = rule->next;
                continue;
            }
        }
        
        // protocol
        if (rule->protocol != PDSFW_PROTO_IP) {
            if (rule->protocol != ip_header->protocol) {
                rule = rule->next;
                continue;
            }
        }
        
        // port
        if (rule->protocol == PDSFW_PROTO_UDP || rule->protocol == PDSFW_PROTO_TCP) {
            // srcport
            if (rule->srcport != 0) {
                if (rule->srcport != srcport) {
                    rule = rule->next;
                    continue;
                }
            }
            
            // dstport
            if (rule->dstport != 0) {
                if (rule->dstport != dstport) {
                    rule = rule->next;
                    continue;
                }
            }
        }
        
        // action
        if (rule->action == PDSFW_ALLOW)
            return NF_ACCEPT;
        else
            return NF_DROP;
    }
    
    return NF_ACCEPT;
    
}

/*
 * Inicializace modulu
 */
int init_module() {
    // Inicializace seznamu pravidel
    pdsfw_init_list(&rule_list);
    
    // Vytvoreni procfs souboru
    if(!(proc = proc_create(FILE_NAME, 0, NULL, &procFops)))
        return -ENOMEM;
    
    // Nastaveni pro zachytavani paketu
    nfho.hook = hook_fnc;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    
    printk(KERN_INFO "pdsfw (xambro03) loaded successfully\n");
    return 0;
}

/*
 * Ukonceni modulu
 */
void cleanup_module() {
    nf_unregister_hook(&nfho);
    remove_proc_entry(FILE_NAME, NULL);
    pdsfw_remove_all(&rule_list);
    printk(KERN_INFO "pdsfw (xambro03) exited successfully\n");
}
